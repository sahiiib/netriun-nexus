CREATE TABLE IF NOT EXISTS workspaces (
 id bigserial PRIMARY KEY,
 name text NOT NULL CHECK(length(name) BETWEEN 2 AND 100),
 slug text NOT NULL UNIQUE CHECK(length(slug) BETWEEN 3 AND 80),
 plan text NOT NULL DEFAULT 'community' CHECK(plan IN ('community','pro','enterprise')),
 user_limit integer NOT NULL DEFAULT 6 CHECK(user_limit BETWEEN 1 AND 10000),
 created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO workspaces(name,slug)
SELECT 'Netriun Nexus Workspace','default'
WHERE (EXISTS(SELECT 1 FROM users) OR EXISTS(SELECT 1 FROM access_groups) OR EXISTS(SELECT 1 FROM cloud_accounts))
  AND NOT EXISTS(SELECT 1 FROM workspaces);

ALTER TABLE users ADD COLUMN IF NOT EXISTS workspace_id bigint REFERENCES workspaces(id) ON DELETE CASCADE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_owner boolean NOT NULL DEFAULT false;
ALTER TABLE access_groups ADD COLUMN IF NOT EXISTS workspace_id bigint REFERENCES workspaces(id) ON DELETE CASCADE;
ALTER TABLE cloud_accounts ADD COLUMN IF NOT EXISTS workspace_id bigint REFERENCES workspaces(id) ON DELETE CASCADE;
ALTER TABLE cloud_accounts ADD COLUMN IF NOT EXISTS provider text NOT NULL DEFAULT 'aws' CHECK(provider IN ('aws','azure','gcp','alibaba'));
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS workspace_id bigint REFERENCES workspaces(id) ON DELETE CASCADE;
ALTER TABLE settings ADD COLUMN IF NOT EXISTS workspace_id bigint REFERENCES workspaces(id) ON DELETE CASCADE;

UPDATE users SET workspace_id=(SELECT id FROM workspaces ORDER BY id LIMIT 1) WHERE workspace_id IS NULL;
UPDATE access_groups SET workspace_id=(SELECT id FROM workspaces ORDER BY id LIMIT 1) WHERE workspace_id IS NULL;
UPDATE cloud_accounts SET workspace_id=(SELECT id FROM workspaces ORDER BY id LIMIT 1) WHERE workspace_id IS NULL;
UPDATE audit_log SET workspace_id=(SELECT id FROM workspaces ORDER BY id LIMIT 1) WHERE workspace_id IS NULL;
UPDATE settings SET workspace_id=(SELECT id FROM workspaces ORDER BY id LIMIT 1) WHERE workspace_id IS NULL AND EXISTS(SELECT 1 FROM workspaces);
DELETE FROM settings WHERE workspace_id IS NULL;

UPDATE users u SET is_owner=true
WHERE u.id=(SELECT min(owner_candidate.id) FROM users owner_candidate WHERE owner_candidate.workspace_id=u.workspace_id AND owner_candidate.role='admin');

ALTER TABLE users ALTER COLUMN workspace_id SET NOT NULL;
ALTER TABLE access_groups ALTER COLUMN workspace_id SET NOT NULL;
ALTER TABLE cloud_accounts ALTER COLUMN workspace_id SET NOT NULL;
ALTER TABLE audit_log ALTER COLUMN workspace_id SET NOT NULL;
ALTER TABLE settings ALTER COLUMN workspace_id SET NOT NULL;

ALTER TABLE access_groups DROP CONSTRAINT IF EXISTS access_groups_name_key;
ALTER TABLE cloud_accounts DROP CONSTRAINT IF EXISTS cloud_accounts_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS access_groups_workspace_name_idx ON access_groups(workspace_id,name);
CREATE UNIQUE INDEX IF NOT EXISTS cloud_accounts_workspace_name_idx ON cloud_accounts(workspace_id,name);
CREATE INDEX IF NOT EXISTS users_workspace_idx ON users(workspace_id);
CREATE INDEX IF NOT EXISTS audit_log_workspace_created_idx ON audit_log(workspace_id,created_at DESC);

ALTER TABLE settings DROP CONSTRAINT IF EXISTS settings_pkey;
ALTER TABLE settings DROP CONSTRAINT IF EXISTS settings_id_check;
ALTER TABLE settings DROP COLUMN IF EXISTS id;
ALTER TABLE settings ADD PRIMARY KEY(workspace_id);
