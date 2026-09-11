package app

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/netriun/nexus/internal/secure"
	"golang.org/x/crypto/bcrypt"
)

type session struct {
	UserID  int64 `json:"user_id"`
	Version int   `json:"version"`
}

const (
	sessionCookie       = "nexus_session"
	legacySessionCookie = "ccmp_session"
)

func sessionToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	c, e := r.Cookie(sessionCookie)
	if e == nil {
		return c.Value
	}
	c, e = r.Cookie(legacySessionCookie)
	if e == nil {
		return c.Value
	}
	return ""
}
func (a *App) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := sessionToken(r)
		if token == "" {
			problem(w, 401, "Sign in to continue")
			return
		}
		raw, err := a.Redis.Get(r.Context(), "session:"+secure.Digest(token)).Result()
		var s session
		if err != nil || json.Unmarshal([]byte(raw), &s) != nil {
			problem(w, 401, "Session expired; sign in again")
			return
		}
		var u User
		err = a.DB.QueryRow(r.Context(), "SELECT u.id,u.workspace_id,w.name,u.username,COALESCE(u.email,''),u.role,u.is_owner,u.session_version FROM users u JOIN workspaces w ON w.id=u.workspace_id WHERE u.id=$1", s.UserID).Scan(&u.ID, &u.WorkspaceID, &u.WorkspaceName, &u.Username, &u.Email, &u.Role, &u.IsOwner, &u.Version)
		if err != nil || u.Version != s.Version {
			problem(w, 401, "Session expired; sign in again")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), userKey, u)))
	})
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	ip := a.clientIP(r)
	key := "login:" + secure.Digest(ip)
	n, err := a.Redis.Eval(r.Context(), `local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],300) end; return n`, []string{key}).Int()
	if err != nil {
		problem(w, 503, "Authentication service unavailable")
		return
	}
	if n > 20 {
		w.Header().Set("Retry-After", "300")
		problem(w, 429, "Too many attempts; try again in five minutes")
		return
	}
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	var u User
	var hash string
	var verified bool
	email, emailErr := normalizeEmail(in.Email)
	if emailErr == nil {
		err = a.DB.QueryRow(r.Context(), "SELECT u.id,u.workspace_id,w.name,u.username,u.email,u.role,u.is_owner,u.session_version,u.password_hash,u.email_verified_at IS NOT NULL FROM users u JOIN workspaces w ON w.id=u.workspace_id WHERE lower(u.email)=$1", email).Scan(&u.ID, &u.WorkspaceID, &u.WorkspaceName, &u.Username, &u.Email, &u.Role, &u.IsOwner, &u.Version, &hash, &verified)
	} else {
		err = emailErr
	}
	if err != nil {
		hash = "$2a$10$7EqJtq98hPqEX7fNZaFWoO5uTktUvMlPtVeziJo.Wu0cnP7eCFUXW"
	}
	passwordErr := bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Password))
	if err != nil || passwordErr != nil {
		problem(w, 401, "Invalid email or password")
		return
	}
	if !verified {
		problem(w, 403, "Verify your email before signing in")
		return
	}
	a.startSession(w, r, u, "auth.login")
}

func (a *App) signup(w http.ResponseWriter, r *http.Request) {
	if !a.allowAttempt(r, "signup", 10) {
		w.Header().Set("Retry-After", "300")
		problem(w, 429, "Too many sign-up attempts; try again in five minutes")
		return
	}
	var in struct {
		Workspace string `json:"workspace"`
		Username  string `json:"username"`
		Email     string `json:"email"`
		Password  string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Workspace = strings.TrimSpace(in.Workspace)
	in.Username = strings.TrimSpace(in.Username)
	email, emailErr := normalizeEmail(in.Email)
	if len(in.Workspace) < 2 || len(in.Workspace) > 100 || len(in.Username) < 3 || len(in.Username) > 100 || emailErr != nil || strongPassword(in.Password) != nil {
		problem(w, 400, "Use a valid email, a 3–100 character username, a 2–100 character workspace, and a strong 10–72 byte password with uppercase, lowercase, number, and symbol")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		problem(w, 500, "Could not create account")
		return
	}
	tx, err := a.DB.Begin(r.Context())
	if err != nil {
		problem(w, 503, "Account service unavailable")
		return
	}
	defer tx.Rollback(r.Context())
	var u User
	u.WorkspaceName, u.Username, u.Email, u.Role, u.IsOwner = in.Workspace, in.Username, email, "admin", true
	slug := "ws-" + secure.Digest(secure.Token())[:12]
	verificationToken := secure.Token()
	if err = tx.QueryRow(r.Context(), "INSERT INTO workspaces(name,slug) VALUES($1,$2) RETURNING id", in.Workspace, slug).Scan(&u.WorkspaceID); err == nil {
		err = tx.QueryRow(r.Context(), "INSERT INTO users(workspace_id,username,email,password_hash,role,is_owner) VALUES($1,$2,$3,$4,'admin',true) RETURNING id,session_version", u.WorkspaceID, in.Username, email, string(hash)).Scan(&u.ID, &u.Version)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), "INSERT INTO settings(workspace_id) VALUES($1)", u.WorkspaceID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), "INSERT INTO email_verification_tokens(user_id,token_digest,expires_at) VALUES($1,$2,now()+interval '24 hours')", u.ID, secure.Digest(verificationToken))
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		problem(w, 409, "Email or username is already in use")
		return
	}
	_ = a.record(r.Context(), u.WorkspaceID, u.ID, u.Username, "workspace.created", slug, map[string]string{"name": in.Workspace})
	if err = a.Mailer.SendVerification(email, in.Username, verificationURL(a.Origin, verificationToken)); err != nil {
		slog.Error("verification email delivery failed", "error", err, "user_id", u.ID)
		problem(w, 503, "Account created, but the verification email could not be sent; use resend verification")
		return
	}
	write(w, http.StatusAccepted, map[string]any{"verification_required": true, "message": "Check your email to verify your account"})
}

func (a *App) resendVerification(w http.ResponseWriter, r *http.Request) {
	if !a.allowAttempt(r, "resend-verification", 5) {
		w.Header().Set("Retry-After", "300")
		problem(w, 429, "Too many requests; try again in five minutes")
		return
	}
	var in struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &in) {
		return
	}
	email, err := normalizeEmail(in.Email)
	if err == nil {
		var id int64
		var username string
		var verified bool
		err = a.DB.QueryRow(r.Context(), "SELECT id,username,email_verified_at IS NOT NULL FROM users WHERE lower(email)=$1", email).Scan(&id, &username, &verified)
		if err == nil && !verified {
			token := secure.Token()
			if _, err = a.DB.Exec(r.Context(), "UPDATE email_verification_tokens SET used_at=now() WHERE user_id=$1 AND used_at IS NULL", id); err == nil {
				_, err = a.DB.Exec(r.Context(), "INSERT INTO email_verification_tokens(user_id,token_digest,expires_at) VALUES($1,$2,now()+interval '24 hours')", id, secure.Digest(token))
			}
			if err == nil {
				if err = a.Mailer.SendVerification(email, username, verificationURL(a.Origin, token)); err != nil {
					slog.Error("verification email resend failed", "error", err, "user_id", id)
				}
			}
		}
	}
	write(w, http.StatusAccepted, map[string]string{"message": "If that address has an unverified account, a new verification email has been sent"})
}

func (a *App) verifyEmail(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		http.Redirect(w, r, "/?verification=invalid", http.StatusSeeOther)
		return
	}
	tx, err := a.DB.Begin(r.Context())
	if err != nil {
		http.Redirect(w, r, "/?verification=invalid", http.StatusSeeOther)
		return
	}
	defer tx.Rollback(r.Context())
	var tokenID, userID, workspaceID int64
	var username string
	err = tx.QueryRow(r.Context(), `SELECT t.id,u.id,u.workspace_id,u.username FROM email_verification_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_digest=$1 AND t.used_at IS NULL AND t.expires_at>now() FOR UPDATE`, secure.Digest(token)).Scan(&tokenID, &userID, &workspaceID, &username)
	if err == nil {
		_, err = tx.Exec(r.Context(), "UPDATE users SET email_verified_at=COALESCE(email_verified_at,now()) WHERE id=$1", userID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), "UPDATE email_verification_tokens SET used_at=now() WHERE user_id=$1 AND used_at IS NULL", userID)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		http.Redirect(w, r, "/?verification=invalid", http.StatusSeeOther)
		return
	}
	_ = a.record(r.Context(), workspaceID, userID, username, "auth.email_verified", strconv.FormatInt(tokenID, 10), nil)
	http.Redirect(w, r, "/?verification=success", http.StatusSeeOther)
}

func (a *App) sendNewVerification(ctx context.Context, userID int64, email, username string) error {
	token := secure.Token()
	if _, err := a.DB.Exec(ctx, "UPDATE email_verification_tokens SET used_at=now() WHERE user_id=$1 AND used_at IS NULL", userID); err != nil {
		return err
	}
	if _, err := a.DB.Exec(ctx, "INSERT INTO email_verification_tokens(user_id,token_digest,expires_at) VALUES($1,$2,now()+interval '24 hours')", userID, secure.Digest(token)); err != nil {
		return err
	}
	return a.Mailer.SendVerification(email, username, verificationURL(a.Origin, token))
}

func (a *App) startSession(w http.ResponseWriter, r *http.Request, u User, action string) {
	token := secure.Token()
	b, _ := json.Marshal(session{u.ID, u.Version})
	if err := a.Redis.Set(r.Context(), "session:"+secure.Digest(token), b, 12*time.Hour).Err(); err != nil {
		problem(w, 503, "Authentication service unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: a.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	_ = a.record(r.Context(), u.WorkspaceID, u.ID, u.Username, action, "", nil)
	write(w, 200, map[string]any{"user": u, "token": token, "expires_in": 43200})
}

func (a *App) allowAttempt(r *http.Request, kind string, limit int) bool {
	key := kind + ":" + secure.Digest(a.clientIP(r))
	n, err := a.Redis.Eval(r.Context(), `local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],300) end; return n`, []string{key}).Int()
	return err == nil && n <= limit
}

func (a *App) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer == nil || !containsIP(a.TrustedProxies, peer) {
		return host
	}

	values := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	if len(values) == 0 || len(values) > 20 || strings.TrimSpace(values[0]) == "" {
		return host
	}
	chain := make([]net.IP, 0, len(values))
	for _, value := range values {
		ip := net.ParseIP(strings.TrimSpace(value))
		if ip == nil {
			return host
		}
		chain = append(chain, ip)
	}
	for i := len(chain) - 1; i >= 0; i-- {
		if !containsIP(a.TrustedProxies, chain[i]) {
			return chain[i].String()
		}
	}
	return chain[0].String()
}

func containsIP(networks []*net.IPNet, ip net.IP) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if err := a.Redis.Del(r.Context(), "session:"+secure.Digest(sessionToken(r))).Err(); err != nil {
		problem(w, 503, "Could not revoke session")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.SecureCookies, SameSite: http.SameSiteStrictMode})
	http.SetCookie(w, &http.Cookie{Name: legacySessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.SecureCookies, SameSite: http.SameSiteStrictMode})
	write(w, 200, map[string]bool{"ok": true})
}
func admin(w http.ResponseWriter, r *http.Request) bool {
	if current(r).Role != "admin" {
		problem(w, 403, "Administrator access required")
		return false
	}
	return true
}
func pathID(w http.ResponseWriter, r *http.Request, key string) (int64, bool) {
	id, e := strconv.ParseInt(r.PathValue(key), 10, 64)
	if e != nil || id < 1 {
		problem(w, 400, "Invalid resource ID")
		return 0, false
	}
	return id, true
}

func (a *App) optionalAccountID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	value := r.URL.Query().Get("account_id")
	if value == "" {
		return 0, true
	}
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id < 1 {
		problem(w, 400, "Invalid cloud account ID")
		return 0, false
	}
	if !a.accountAccess(r, id, "view") {
		problem(w, 403, "Cloud account access required")
		return 0, false
	}
	return id, true
}

// The same tenant and account scope is applied to inventory and direct resource access.
const scopeSQL = `(a.workspace_id=$3 AND ($1::boolean OR EXISTS(SELECT 1 FROM user_groups ug JOIN access_groups g ON g.id=ug.group_id WHERE ug.user_id=$2 AND ug.group_id=a.group_id AND g.view_dashboard)))`

func (a *App) accountAccess(r *http.Request, id int64, mode string) bool {
	u := current(r)
	if u.Role == "admin" {
		var allowed bool
		return a.DB.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM cloud_accounts WHERE id=$1 AND workspace_id=$2)", id, u.WorkspaceID).Scan(&allowed) == nil && allowed
	}
	var allowed bool
	query := `SELECT EXISTS(SELECT 1 FROM cloud_accounts a JOIN user_groups ug ON ug.group_id=a.group_id JOIN access_groups g ON g.id=ug.group_id WHERE a.id=$1 AND a.workspace_id=$3 AND ug.user_id=$2 AND `
	switch mode {
	case "manage":
		query += `g.manage_cloud_accounts AND ug.role='manager'`
	case "operate":
		query += `g.view_dashboard AND ug.role IN ('operator','manager')`
	default:
		query += `g.view_dashboard`
	}
	query += `)`
	return a.DB.QueryRow(r.Context(), query, id, u.ID, u.WorkspaceID).Scan(&allowed) == nil && allowed
}
func (a *App) groupAccess(r *http.Request, id int64, mode string) bool {
	u := current(r)
	if u.Role == "admin" {
		var allowed bool
		return a.DB.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM access_groups WHERE id=$1 AND workspace_id=$2)", id, u.WorkspaceID).Scan(&allowed) == nil && allowed
	}
	column := "manage_cloud_accounts"
	if mode == "members" {
		column = "manage_group_members"
	}
	var allowed bool
	return a.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM user_groups ug JOIN access_groups g ON g.id=ug.group_id WHERE ug.user_id=$1 AND g.id=$2 AND g.workspace_id=$3 AND ug.role='manager' AND g.`+column+`)`, u.ID, id, u.WorkspaceID).Scan(&allowed) == nil && allowed
}
