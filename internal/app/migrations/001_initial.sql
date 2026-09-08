CREATE TABLE IF NOT EXISTS users (
 id bigserial PRIMARY KEY, username text NOT NULL UNIQUE CHECK(length(username) BETWEEN 3 AND 100),
 password_hash text NOT NULL, role text NOT NULL DEFAULT 'user' CHECK(role IN ('admin','user')),
 session_version integer NOT NULL DEFAULT 1, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS access_groups (
 id bigserial PRIMARY KEY, name text NOT NULL UNIQUE CHECK(length(name) BETWEEN 1 AND 100), description text NOT NULL DEFAULT '',
 view_dashboard boolean NOT NULL DEFAULT true, manage_cloud_accounts boolean NOT NULL DEFAULT false,
 manage_group_members boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS user_groups (
 user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE, group_id bigint NOT NULL REFERENCES access_groups(id) ON DELETE CASCADE,
 role text NOT NULL CHECK(role IN ('viewer','operator','manager')), PRIMARY KEY(user_id,group_id)
);
CREATE TABLE IF NOT EXISTS cloud_accounts (
 id bigserial PRIMARY KEY, name text NOT NULL UNIQUE CHECK(length(name) BETWEEN 1 AND 100), owner text NOT NULL DEFAULT '',
 group_id bigint REFERENCES access_groups(id) ON DELETE SET NULL, credentials text NOT NULL,
 regions text[] NOT NULL DEFAULT '{}', last_sync_at timestamptz, sync_error text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS instances (
 id bigserial PRIMARY KEY, account_id bigint NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
 instance_id text NOT NULL, region text NOT NULL, name text NOT NULL DEFAULT '', state text NOT NULL,
 instance_type text NOT NULL, public_ip text NOT NULL DEFAULT '', private_ip text NOT NULL DEFAULT '',
 details jsonb NOT NULL DEFAULT '{}', seen_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(account_id,region,instance_id)
);
CREATE INDEX IF NOT EXISTS instances_account_idx ON instances(account_id);
CREATE INDEX IF NOT EXISTS user_groups_group_idx ON user_groups(group_id);
CREATE TABLE IF NOT EXISTS audit_log (
 id bigserial PRIMARY KEY, user_id bigint REFERENCES users(id) ON DELETE SET NULL, username text NOT NULL DEFAULT 'system',
 action text NOT NULL, target text NOT NULL DEFAULT '', details jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS settings (
 id boolean PRIMARY KEY DEFAULT true CHECK(id), collector_interval_minutes integer NOT NULL DEFAULT 30 CHECK(collector_interval_minutes BETWEEN 1 AND 10080),
 audit_retention_days integer NOT NULL DEFAULT 90 CHECK(audit_retention_days BETWEEN 7 AND 3650), last_collector_run_at timestamptz
);
INSERT INTO settings(id) VALUES(true) ON CONFLICT DO NOTHING;
