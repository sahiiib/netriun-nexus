ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS sso_required boolean NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS identity_providers (
 id bigserial PRIMARY KEY,
 workspace_id bigint NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 public_id text NOT NULL UNIQUE CHECK(length(public_id) BETWEEN 20 AND 100),
 name text NOT NULL CHECK(length(name) BETWEEN 1 AND 100),
 protocol text NOT NULL CHECK(protocol IN ('oidc','saml')),
 enabled boolean NOT NULL DEFAULT false,
 jit_provisioning boolean NOT NULL DEFAULT false,
 config_encrypted text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(id,workspace_id),
 UNIQUE(workspace_id,name)
);

CREATE TABLE IF NOT EXISTS external_identities (
 id bigserial PRIMARY KEY,
 workspace_id bigint NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 provider_id bigint NOT NULL,
 user_id bigint NOT NULL,
 subject text NOT NULL CHECK(length(subject) BETWEEN 1 AND 2048),
 email text NOT NULL,
 attributes jsonb NOT NULL DEFAULT '{}'::jsonb,
 last_login_at timestamptz NOT NULL DEFAULT now(),
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(provider_id,workspace_id) REFERENCES identity_providers(id,workspace_id) ON DELETE CASCADE,
 FOREIGN KEY(user_id,workspace_id) REFERENCES users(id,workspace_id) ON DELETE CASCADE,
 UNIQUE(provider_id,subject),
 UNIQUE(provider_id,user_id)
);

CREATE TABLE IF NOT EXISTS identity_group_mappings (
 id bigserial PRIMARY KEY,
 workspace_id bigint NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 provider_id bigint NOT NULL,
 external_group text NOT NULL CHECK(length(external_group) BETWEEN 1 AND 512),
 group_id bigint NOT NULL,
 membership_role text NOT NULL DEFAULT 'viewer' CHECK(membership_role IN ('viewer','operator','manager')),
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(provider_id,workspace_id) REFERENCES identity_providers(id,workspace_id) ON DELETE CASCADE,
 FOREIGN KEY(group_id,workspace_id) REFERENCES access_groups(id,workspace_id) ON DELETE CASCADE,
 UNIQUE(provider_id,external_group,group_id)
);

CREATE TABLE IF NOT EXISTS sso_membership_grants (
 id bigserial PRIMARY KEY,
 workspace_id bigint NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 provider_id bigint NOT NULL,
 user_id bigint NOT NULL,
 group_id bigint NOT NULL,
 external_group text NOT NULL,
 role text NOT NULL CHECK(role IN ('viewer','operator','manager')),
 synced_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(provider_id,workspace_id) REFERENCES identity_providers(id,workspace_id) ON DELETE CASCADE,
 FOREIGN KEY(user_id,workspace_id) REFERENCES users(id,workspace_id) ON DELETE CASCADE,
 FOREIGN KEY(group_id,workspace_id) REFERENCES access_groups(id,workspace_id) ON DELETE CASCADE,
 UNIQUE(provider_id,user_id,group_id,external_group)
);

CREATE INDEX IF NOT EXISTS external_identities_user_idx ON external_identities(workspace_id,user_id);
CREATE INDEX IF NOT EXISTS identity_group_mappings_provider_idx ON identity_group_mappings(workspace_id,provider_id);
CREATE INDEX IF NOT EXISTS sso_membership_grants_user_idx ON sso_membership_grants(workspace_id,user_id,group_id);

CREATE OR REPLACE VIEW effective_user_groups AS
 SELECT ug.user_id,ug.group_id,ug.role,'manual'::text AS source_type,''::text AS source_ref
 FROM user_groups ug
 UNION ALL
 SELECT sg.user_id,sg.group_id,sg.role,'sso'::text AS source_type,
        sg.provider_id::text || ':' || sg.external_group AS source_ref
 FROM sso_membership_grants sg;

COMMENT ON TABLE external_identities IS 'Stable IdP subject links. Email is descriptive and is never the identity key.';
COMMENT ON TABLE sso_membership_grants IS 'SSO-derived team grants kept separate from manual user_groups memberships.';
