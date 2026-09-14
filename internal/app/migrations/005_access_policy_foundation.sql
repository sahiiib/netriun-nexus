CREATE TABLE IF NOT EXISTS access_roles (
 id bigserial PRIMARY KEY,
 workspace_id bigint NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 key text NOT NULL CHECK(key ~ '^[a-z][a-z0-9_-]{1,62}$'),
 name text NOT NULL CHECK(length(name) BETWEEN 1 AND 100),
 description text NOT NULL DEFAULT '',
 permissions text[] NOT NULL DEFAULT '{}',
 built_in boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(workspace_id,key),
 UNIQUE(id,workspace_id)
);

CREATE OR REPLACE FUNCTION seed_nexus_access_roles() RETURNS trigger AS $$
BEGIN
 INSERT INTO access_roles(workspace_id,key,name,description,permissions,built_in) VALUES
  (NEW.id,'viewer','Viewer','Read cloud inventory and service details',ARRAY['account.view','compute.view','eds.view'],true),
  (NEW.id,'operator','Operator','Viewer access plus compute and desktop lifecycle operations',ARRAY['account.view','compute.view','compute.operate','eds.view','eds.operate'],true),
  (NEW.id,'account_manager','Account Manager','Operate resources and manage the cloud connection',ARRAY['account.view','account.manage','compute.view','compute.operate','eds.view','eds.operate','eds.manage'],true)
 ON CONFLICT(workspace_id,key) DO NOTHING;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS workspaces_seed_access_roles ON workspaces;
CREATE TRIGGER workspaces_seed_access_roles
AFTER INSERT ON workspaces
FOR EACH ROW EXECUTE FUNCTION seed_nexus_access_roles();

INSERT INTO access_roles(workspace_id,key,name,description,permissions,built_in)
SELECT w.id,r.key,r.name,r.description,r.permissions,true
FROM workspaces w
CROSS JOIN (VALUES
 ('viewer','Viewer','Read cloud inventory and service details',ARRAY['account.view','compute.view','eds.view']::text[]),
 ('operator','Operator','Viewer access plus compute and desktop lifecycle operations',ARRAY['account.view','compute.view','compute.operate','eds.view','eds.operate']::text[]),
 ('account_manager','Account Manager','Operate resources and manage the cloud connection',ARRAY['account.view','account.manage','compute.view','compute.operate','eds.view','eds.operate','eds.manage']::text[])
) AS r(key,name,description,permissions)
ON CONFLICT(workspace_id,key) DO NOTHING;

ALTER TABLE users ADD CONSTRAINT users_id_workspace_unique UNIQUE(id,workspace_id);
ALTER TABLE access_groups ADD CONSTRAINT access_groups_id_workspace_unique UNIQUE(id,workspace_id);
ALTER TABLE cloud_accounts ADD CONSTRAINT cloud_accounts_id_workspace_unique UNIQUE(id,workspace_id);

CREATE TABLE IF NOT EXISTS account_access_assignments (
 id bigserial PRIMARY KEY,
 workspace_id bigint NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 principal_type text NOT NULL CHECK(principal_type IN ('user','team')),
 user_id bigint,
 group_id bigint,
 cloud_account_id bigint NOT NULL,
 role_id bigint NOT NULL,
 service_key text NOT NULL DEFAULT '*' CHECK(service_key ~ '^(\*|[a-z][a-z0-9_.-]{1,62})$'),
 source_type text NOT NULL DEFAULT 'manual' CHECK(source_type IN ('manual','sso')),
 source_ref text NOT NULL DEFAULT '',
 created_by bigint REFERENCES users(id) ON DELETE SET NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 CHECK((principal_type='user' AND user_id IS NOT NULL AND group_id IS NULL) OR (principal_type='team' AND group_id IS NOT NULL AND user_id IS NULL)),
 FOREIGN KEY(user_id,workspace_id) REFERENCES users(id,workspace_id) ON DELETE CASCADE,
 FOREIGN KEY(group_id,workspace_id) REFERENCES access_groups(id,workspace_id) ON DELETE CASCADE,
 FOREIGN KEY(cloud_account_id,workspace_id) REFERENCES cloud_accounts(id,workspace_id) ON DELETE CASCADE,
 FOREIGN KEY(role_id,workspace_id) REFERENCES access_roles(id,workspace_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX IF NOT EXISTS account_access_user_source_idx
 ON account_access_assignments(workspace_id,user_id,cloud_account_id,service_key,source_type,source_ref)
 WHERE principal_type='user';
CREATE UNIQUE INDEX IF NOT EXISTS account_access_team_source_idx
 ON account_access_assignments(workspace_id,group_id,cloud_account_id,service_key,source_type,source_ref)
 WHERE principal_type='team';
CREATE INDEX IF NOT EXISTS account_access_account_idx ON account_access_assignments(workspace_id,cloud_account_id);
CREATE INDEX IF NOT EXISTS account_access_user_idx ON account_access_assignments(workspace_id,user_id) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS account_access_group_idx ON account_access_assignments(workspace_id,group_id) WHERE group_id IS NOT NULL;

COMMENT ON TABLE account_access_assignments IS 'Account/service-scoped grants. If an account has no assignments, the legacy access-group policy remains authoritative during migration.';
