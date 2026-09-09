package app

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/netriun/nexus/internal/secure"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

//go:embed migrations/*.sql web/*
var assets embed.FS

type App struct {
	DB             *pgxpool.Pool
	Redis          *redis.Client
	Vault          *secure.Vault
	SecureCookies  bool
	Origin         string
	TrustedProxies []*net.IPNet
}
type User struct {
	ID            int64  `json:"id"`
	WorkspaceID   int64  `json:"-"`
	WorkspaceName string `json:"workspace"`
	Username      string `json:"username"`
	Role          string `json:"role"`
	IsOwner       bool   `json:"is_owner"`
	Version       int    `json:"-"`
}
type contextKey string

const userKey contextKey = "user"

func current(r *http.Request) User { return r.Context().Value(userKey).(User) }
func New(ctx context.Context) (*App, error) {
	cfg, err := loadRuntimeConfig()
	if err != nil {
		return nil, err
	}
	v, err := secure.NewVault(cfg.encryptionKey)
	if err != nil {
		return nil, err
	}
	db, err := pgxpool.New(ctx, cfg.databaseURL)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (*App, error) { db.Close(); return nil, e }
	if err = db.Ping(ctx); err != nil {
		return fail(err)
	}
	opt, err := redis.ParseURL(cfg.redisURL)
	if err != nil {
		return fail(err)
	}
	rc := redis.NewClient(opt)
	if err = rc.Ping(ctx).Err(); err != nil {
		rc.Close()
		return fail(err)
	}
	a := &App{DB: db, Redis: rc, Vault: v, SecureCookies: cfg.secureCookies, Origin: cfg.origin, TrustedProxies: cfg.trustedProxies}
	if err = a.migrate(ctx); err != nil {
		a.Close()
		return nil, err
	}
	if err = a.bootstrap(ctx); err != nil {
		a.Close()
		return nil, err
	}
	return a, nil
}
func (a *App) Close() { a.DB.Close(); a.Redis.Close() }
func (a *App) bootstrap(ctx context.Context) error {
	name, pass := os.Getenv("ADMIN_USERNAME"), os.Getenv("ADMIN_PASSWORD")
	var count int
	if err := a.DB.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	if len(name) < 3 || len(pass) < 12 || len(pass) > 72 {
		return errors.New("first boot requires ADMIN_USERNAME (3+ characters) and ADMIN_PASSWORD (12–72 bytes)")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var workspaceID int64
	if err = tx.QueryRow(ctx, "INSERT INTO workspaces(name,slug) VALUES('Netriun Nexus Workspace','default') RETURNING id").Scan(&workspaceID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO users(workspace_id,username,password_hash,role,is_owner) VALUES($1,$2,$3,'admin',true)", workspaceID, name, string(hash)); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO settings(workspace_id) VALUES($1)", workspaceID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func problem(w http.ResponseWriter, status int, msg string) {
	write(w, status, map[string]string{"error": msg})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		problem(w, 415, "Content-Type must be application/json")
		return false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		problem(w, 400, "Invalid JSON request")
		return false
	}
	if d.Decode(new(any)) != io.EOF {
		problem(w, 400, "Expected one JSON object")
		return false
	}
	return true
}
func dbError(w http.ResponseWriter, err error) {
	if errors.Is(err, pgx.ErrNoRows) {
		problem(w, 404, "Resource not found")
		return
	}
	slog.Error("database operation failed", "error", err)
	problem(w, 409, "Operation could not be completed; check references and unique names")
}
func (a *App) audit(r *http.Request, action, target string, details any) {
	u := current(r)
	_ = a.record(r.Context(), u.WorkspaceID, u.ID, u.Username, action, target, details)
}
func (a *App) record(ctx context.Context, workspaceID, uid int64, name, action, target string, details any) error {
	b, _ := json.Marshal(details)
	var id any
	if uid > 0 {
		id = uid
	}
	if _, err := a.DB.Exec(ctx, "INSERT INTO audit_log(workspace_id,user_id,username,action,target,details) VALUES($1,$2,$3,$4,$5,$6)", workspaceID, id, name, action, target, b); err != nil {
		slog.Error("audit write failed", "error", err)
		return err
	}
	return nil
}
func (a *App) list(w http.ResponseWriter, r *http.Request, query string, args ...any) {
	rows, err := a.DB.Query(r.Context(), query, args...)
	if err != nil {
		dbError(w, err)
		return
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var b []byte
		if err = rows.Scan(&b); err != nil {
			dbError(w, err)
			return
		}
		out = append(out, b)
	}
	if err = rows.Err(); err != nil {
		dbError(w, err)
		return
	}
	write(w, 200, map[string]any{"data": out})
}
func (a *App) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { write(w, 200, map[string]string{"status": "ok"}) })
	m.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if a.DB.Ping(ctx) != nil || a.Redis.Ping(ctx).Err() != nil {
			problem(w, 503, "Dependencies unavailable")
			return
		}
		write(w, 200, map[string]string{"status": "ready"})
	})
	m.HandleFunc("POST /api/v1/auth/login", a.login)
	m.HandleFunc("POST /api/v1/auth/signup", a.signup)
	routes := map[string]http.HandlerFunc{
		"GET /api/v1/summary":      a.summary,
		"GET /api/v1/auth/me":      func(w http.ResponseWriter, r *http.Request) { write(w, 200, current(r)) },
		"POST /api/v1/auth/logout": a.logout,
		"GET /api/v1/instances":    a.instances, "GET /api/v1/instances/{id}": a.instance, "POST /api/v1/instances/{id}/actions": a.action,
		"GET /api/v1/accounts": a.accounts, "POST /api/v1/accounts": a.saveAccount, "PUT /api/v1/accounts/{id}": a.saveAccount, "DELETE /api/v1/accounts/{id}": a.deleteAccount,
		"GET /api/v1/accounts/{id}/eds/desktops": a.edsDesktops, "POST /api/v1/accounts/{id}/eds/desktops": a.createEDSDesktop,
		"GET /api/v1/accounts/{id}/eds/catalog":                                  a.edsCatalog,
		"GET /api/v1/accounts/{id}/eds/regions":                                  a.edsRegions,
		"POST /api/v1/accounts/{id}/eds/desktops/{desktopID}/actions":            a.edsDesktopAction,
		"POST /api/v1/accounts/{id}/eds/desktops/{desktopID}/renew":              a.renewEDSDesktop,
		"POST /api/v1/accounts/{id}/eds/desktops/{desktopID}/users":              a.changeEDSEntitlement,
		"POST /api/v1/accounts/{id}/eds/desktops/{desktopID}/policy":             a.changeEDSPolicy,
		"POST /api/v1/accounts/{id}/eds/desktops/{desktopID}/maintenance":        a.setEDSMaintenance,
		"POST /api/v1/accounts/{id}/eds/desktops/{desktopID}/commands":           a.runEDSCommand,
		"GET /api/v1/accounts/{id}/eds/desktops/{desktopID}/commands/{invokeID}": a.edsCommandResult,
		"POST /api/v1/accounts/{id}/eds/desktops/{desktopID}/billing":            a.changeEDSBilling,
		"GET /api/v1/accounts/{id}/eds/users":                                    a.edsUsers, "POST /api/v1/accounts/{id}/eds/users": a.createEDSUser,
		"GET /api/v1/groups": a.groups, "POST /api/v1/groups": a.saveGroup, "PUT /api/v1/groups/{id}": a.saveGroup, "DELETE /api/v1/groups/{id}": a.deleteGroup,
		"GET /api/v1/users": a.users, "POST /api/v1/users": a.saveUser, "PUT /api/v1/users/{id}": a.saveUser, "DELETE /api/v1/users/{id}": a.deleteUser,
		"GET /api/v1/memberships": a.memberships, "PUT /api/v1/groups/{id}/members/{userID}": a.saveMembership, "DELETE /api/v1/groups/{id}/members/{userID}": a.deleteMembership,
		"GET /api/v1/activity": a.activity, "GET /api/v1/settings": a.settings, "PUT /api/v1/settings": a.saveSettings, "POST /api/v1/collector/run": a.triggerCollector,
	}
	for pattern, h := range routes {
		m.Handle(pattern, a.auth(h))
	}
	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { problem(w, 404, "API route not found") })
	web, _ := fs.Sub(assets, "web")
	m.Handle("/", http.FileServer(http.FS(web)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		requestID := secure.Token()
		w.Header().Set("X-Request-ID", requestID)
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			if (r.URL.Path == "/healthz" || r.URL.Path == "/readyz") && sw.status < 400 {
				return
			}
			slog.Info("http request", "request_id", requestID, "method", r.Method, "path", r.URL.Path, "status", sw.status, "bytes", sw.bytes, "duration_ms", time.Since(started).Milliseconds(), "client_ip", a.clientIP(r))
		}()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		} else if r.Method == "GET" || r.Method == "HEAD" {
			w.Header().Set("Cache-Control", "no-cache")
		}
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
			if origin := r.Header.Get("Origin"); origin != "" && origin != a.Origin {
				problem(sw, 403, "Origin not allowed")
				return
			}
		}
		defer func() {
			if v := recover(); v != nil {
				slog.Error("request panic", "error", fmt.Sprint(v))
				problem(sw, 500, "Internal server error")
			}
		}()
		m.ServeHTTP(sw, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	bytes       int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += n
	return n, err
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
