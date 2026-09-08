// migrate-legacy reads a legacy database through sqlite3 in read-only mode.
// It imports atomically into a PostgreSQL database initialized by Netriun Nexus.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/netriun/nexus/internal/secure"
)

type row map[string]any

func text(r row, k string) string {
	if r[k] == nil {
		return ""
	}
	return fmt.Sprint(r[k])
}
func number(r row, k string) int64 { v, _ := strconv.ParseInt(text(r, k), 10, 64); return v }
func nullable(r row, k string) any {
	if r[k] == nil {
		return nil
	}
	return number(r, k)
}
func read(path, table string) ([]row, error) {
	out, err := exec.Command("sqlite3", "-readonly", "-json", path, "SELECT * FROM "+table).Output()
	if err != nil {
		return nil, fmt.Errorf("read legacy %s: %w", table, err)
	}
	var result []row
	if len(out) == 0 {
		return result, nil
	}
	d := json.NewDecoder(bytes.NewReader(out))
	d.UseNumber()
	err = d.Decode(&result)
	return result, err
}
func main() {
	source := flag.String("source", "", "Path to a consistent legacy monitor.db backup")
	apply := flag.Bool("apply", false, "Commit the import (default validates then rolls back)")
	flag.Parse()
	if err := run(*source, *apply); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(source string, apply bool) error {
	if source == "" {
		return errors.New("usage: migrate-legacy -source /path/to/backup.db [-apply]")
	}
	if _, err := os.Stat(source); err != nil {
		return err
	}
	v, err := secure.NewVault(os.Getenv("ENCRYPTION_KEY"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	db, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	defer db.Close()
	tables := []string{"users", "access_groups", "user_groups", "aws_accounts", "ec2_instances", "account_activity_log", "logs", "app_settings"}
	data := map[string][]row{}
	for _, t := range tables {
		data[t], err = read(source, t)
		if err != nil {
			return err
		}
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Run offline. Locks prevent a concurrent API request or collector from racing the import.
	if _, err = tx.Exec(ctx, "LOCK TABLE users,access_groups,user_groups,cloud_accounts,instances,audit_log,settings IN ACCESS EXCLUSIVE MODE"); err != nil {
		return fmt.Errorf("initialize the target schema with Netriun Nexus first: %w", err)
	}
	var count int
	err = tx.QueryRow(ctx, "SELECT (SELECT count(*) FROM cloud_accounts)+(SELECT count(*) FROM access_groups)+(SELECT count(*) FROM instances)+(SELECT count(*) FROM users)").Scan(&count)
	if err != nil {
		return err
	}
	if count > 1 {
		return errors.New("target must be a fresh Netriun Nexus database containing at most the bootstrap user")
	}
	var workspaceID int64
	if err = tx.QueryRow(ctx, "SELECT id FROM workspaces ORDER BY id LIMIT 1").Scan(&workspaceID); err != nil {
		return errors.New("target must contain the bootstrap workspace")
	}
	if len(data["users"]) == 0 {
		return errors.New("legacy database has no users")
	}
	admins := 0
	for _, u := range data["users"] {
		if text(u, "role") == "admin" {
			admins++
		}
		h := text(u, "password_hash")
		if len(h) != 60 || !(len(h) > 4 && (h[:4] == "$2y$" || h[:4] == "$2a$" || h[:4] == "$2b$")) {
			return errors.New("unsupported legacy password hash; bcrypt hashes are required")
		}
	}
	if admins == 0 {
		return errors.New("legacy database has no administrator")
	}
	if _, err = tx.Exec(ctx, "DELETE FROM audit_log; DELETE FROM users"); err != nil {
		return err
	}
	insert := func(sql string, args ...any) error { _, e := tx.Exec(ctx, sql, args...); return e }
	for _, r := range data["users"] {
		if err = insert("INSERT INTO users(id,workspace_id,username,password_hash,role) VALUES($1,$2,$3,$4,$5)", number(r, "id"), workspaceID, text(r, "username"), text(r, "password_hash"), text(r, "role")); err != nil {
			return fmt.Errorf("import users: %w", err)
		}
	}
	if err = insert("UPDATE users SET is_owner=true WHERE id=(SELECT min(id) FROM users WHERE workspace_id=$1 AND role='admin')", workspaceID); err != nil {
		return err
	}
	for _, r := range data["access_groups"] {
		p := map[string]bool{"view_dashboard": true}
		if raw := text(r, "security_policy"); raw != "" {
			if err = json.Unmarshal([]byte(raw), &p); err != nil {
				return fmt.Errorf("invalid group policy for id %d", number(r, "id"))
			}
		}
		if err = insert("INSERT INTO access_groups(id,workspace_id,name,description,view_dashboard,manage_cloud_accounts,manage_group_members) VALUES($1,$2,$3,$4,$5,$6,$7)", number(r, "id"), workspaceID, text(r, "name"), text(r, "description"), p["view_dashboard"], p["manage_cloud_accounts"], p["manage_group_members"]); err != nil {
			return err
		}
	}
	for _, r := range data["user_groups"] {
		role := text(r, "role")
		if role == "group_admin" {
			role = "manager"
		}
		if err = insert("INSERT INTO user_groups(user_id,group_id,role) VALUES($1,$2,$3)", number(r, "user_id"), number(r, "group_id"), role); err != nil {
			return err
		}
	}
	for _, r := range data["aws_accounts"] {
		credentials, _ := json.Marshal(map[string]string{"access_key_id": text(r, "access_key_id"), "secret_access_key": text(r, "secret_access_key")})
		if err = insert("INSERT INTO cloud_accounts(id,workspace_id,name,provider,owner,group_id,credentials) VALUES($1,$2,$3,'aws',$4,$5,$6)", number(r, "id"), workspaceID, text(r, "account_name"), text(r, "owner"), nullable(r, "group_id"), v.Encrypt(string(credentials))); err != nil {
			return fmt.Errorf("import account id %d: constraint or database error", number(r, "id"))
		}
	}
	for _, r := range data["ec2_instances"] {
		details := map[string]any{}
		for _, k := range []string{"launch_time", "vpc_id", "subnet_id", "iam_instance_profile"} {
			details[k] = r[k]
		}
		for _, k := range []string{"tags", "security_groups"} {
			var value any
			raw := text(r, k)
			if raw != "" {
				if err = json.Unmarshal([]byte(raw), &value); err != nil {
					return fmt.Errorf("invalid %s for instance row %d", k, number(r, "id"))
				}
			}
			dest := k
			if k == "security_groups" {
				dest = "security_group_ids"
			}
			details[dest] = value
		}
		b, _ := json.Marshal(details)
		if err = insert("INSERT INTO instances(id,account_id,instance_id,region,name,state,instance_type,public_ip,private_ip,details) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", number(r, "id"), number(r, "aws_account_id"), text(r, "instance_id"), text(r, "region"), text(r, "name"), text(r, "state"), text(r, "instance_type"), text(r, "public_ip"), text(r, "private_ip"), b); err != nil {
			return err
		}
	}
	for _, table := range []string{"account_activity_log", "logs"} {
		for _, r := range data[table] {
			stamp := text(r, "created_at")
			if stamp == "" {
				stamp = text(r, "timestamp")
			}
			if stamp == "" {
				stamp = time.Now().UTC().Format(time.RFC3339)
			}
			details, _ := json.Marshal(map[string]any{"legacy_table": table, "legacy_id": r["id"], "details": r["details"], "account_id": r["aws_account_id"], "group_id": r["group_id"]})
			if err = insert("INSERT INTO audit_log(workspace_id,user_id,username,action,target,details,created_at) VALUES($1,(SELECT id FROM users WHERE id=$2),COALESCE((SELECT username FROM users WHERE id=$2),'system'),$3,$4,$5,$6::timestamptz)", workspaceID, nullable(r, "user_id"), text(r, "action"), text(r, "aws_account_id"), details, stamp); err != nil {
				return err
			}
		}
	}
	for _, r := range data["app_settings"] {
		if text(r, "key") == "collector_interval_minutes" {
			n, _ := strconv.Atoi(text(r, "value"))
			if n >= 1 && n <= 10080 {
				if err = insert("UPDATE settings SET collector_interval_minutes=$1 WHERE workspace_id=$2", n, workspaceID); err != nil {
					return err
				}
			}
		}
	}
	// Delay the first sync for review; old logrotate options are replaced by container rotation.
	if err = insert("UPDATE settings SET last_collector_run_at=now() WHERE workspace_id=$1", workspaceID); err != nil {
		return err
	}
	for _, table := range []string{"users", "access_groups", "cloud_accounts", "instances", "audit_log"} {
		if err = resetSequence(ctx, tx, table); err != nil {
			return err
		}
	}
	for _, table := range tables {
		fmt.Printf("Validated %-24s %d rows\n", table, len(data[table]))
	}
	if !apply {
		fmt.Println("Dry run successful; transaction rolled back. Use -apply to commit.")
		return nil
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Println("Import committed. Clear Netriun Nexus Redis sessions before restarting the application.")
	return nil
}
func resetSequence(ctx context.Context, tx pgx.Tx, table string) error {
	var next int64
	if err := tx.QueryRow(ctx, "SELECT COALESCE(max(id),0)+1 FROM "+table).Scan(&next); err != nil {
		return err
	}
	// ALTER SEQUENCE is transactional, unlike setval, including on dry runs.
	_, err := tx.Exec(ctx, fmt.Sprintf("ALTER SEQUENCE %s_id_seq RESTART WITH %d", table, next))
	return err
}
