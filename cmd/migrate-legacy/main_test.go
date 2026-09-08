package main

import (
	"context"
	"encoding/base64"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigration(t *testing.T) {
	dsn := os.Getenv("TEST_MIGRATION_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_MIGRATION_DATABASE_URL to an isolated ccmp_test migration database")
	}
	if !strings.Contains(dsn, "ccmp_test") {
		t.Fatal("unsafe target")
	}
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("sqlite3 required")
	}
	t.Setenv("DATABASE_URL", dsn)
	t.Setenv("ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	schema, err := os.ReadFile("../../internal/app/schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, string(schema)); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, "TRUNCATE users,access_groups,cloud_accounts,instances,audit_log RESTART IDENTITY CASCADE"); err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("legacy-password"), bcrypt.MinCost)
	source := filepath.Join(t.TempDir(), "legacy.db")
	sql := `CREATE TABLE users(id,username,password_hash,role); CREATE TABLE access_groups(id,name,description,security_policy); CREATE TABLE user_groups(user_id,group_id,role); CREATE TABLE aws_accounts(id,account_name,owner,group_id,access_key_id,secret_access_key); CREATE TABLE ec2_instances(id,aws_account_id,instance_id,region,name,state,instance_type,public_ip,private_ip,launch_time,vpc_id,subnet_id,iam_instance_profile,tags,security_groups); CREATE TABLE account_activity_log(id,created_at,user_id,aws_account_id,group_id,action,details); CREATE TABLE logs(id,timestamp,action,details,user_id); CREATE TABLE app_settings(key,value);
 INSERT INTO users VALUES(7,'legacyadmin','` + strings.Replace(string(hash), "$2a$", "$2y$", 1) + `','admin');
 INSERT INTO access_groups VALUES(4,'Legacy group','Imported','{"view_dashboard":true}'); INSERT INTO user_groups VALUES(7,4,'group_admin');
 INSERT INTO aws_accounts VALUES(3,'Legacy AWS','Owner',4,'testkey','testsecret');
 INSERT INTO ec2_instances VALUES(8,3,'i-test','us-east-1','Test','running','t3.micro','','',NULL,'vpc-test','subnet-test','','{}','[]');
 INSERT INTO logs VALUES(1,'2026-01-01 00:00:00','legacy.action','details',7);
 INSERT INTO app_settings VALUES('collector_interval_minutes','60');`
	cmd := exec.Command("sqlite3", source)
	cmd.Stdin = strings.NewReader(sql)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fixture: %s %v", out, err)
	}
	if err = run(source, false); err != nil {
		t.Fatal(err)
	}
	var n int
	db.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&n)
	if n != 0 {
		t.Fatal("dry run persisted users")
	}
	var sequence int64
	db.QueryRow(ctx, "SELECT last_value FROM users_id_seq").Scan(&sequence)
	if sequence != 1 {
		t.Fatal("dry run mutated sequence")
	}
	if err = run(source, true); err != nil {
		t.Fatal(err)
	}
	var role, encrypted, password string
	db.QueryRow(ctx, "SELECT role FROM user_groups").Scan(&role)
	if role != "manager" {
		t.Fatal("legacy role not mapped")
	}
	db.QueryRow(ctx, "SELECT credentials FROM cloud_accounts").Scan(&encrypted)
	if strings.Contains(encrypted, "testsecret") {
		t.Fatal("plaintext secret imported")
	}
	db.QueryRow(ctx, "SELECT password_hash FROM users WHERE id=7").Scan(&password)
	if err = bcrypt.CompareHashAndPassword([]byte(password), []byte("legacy-password")); err != nil {
		t.Fatal("legacy PHP bcrypt login failed")
	}
	var next int64
	db.QueryRow(ctx, "INSERT INTO users(username,password_hash,role) VALUES('next','unused','user') RETURNING id").Scan(&next)
	if next != 8 {
		t.Fatalf("sequence wrong: %d", next)
	}
	if err = run(source, true); err == nil {
		t.Fatal("populated target accepted")
	}
}
