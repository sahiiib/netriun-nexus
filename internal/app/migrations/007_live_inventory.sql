ALTER TABLE settings DROP COLUMN IF EXISTS collector_interval_minutes;

CREATE TABLE IF NOT EXISTS service_snapshots (
 id bigserial PRIMARY KEY,
 workspace_id bigint NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 account_id bigint NOT NULL,
 service_key text NOT NULL CHECK(service_key ~ '^[a-z][a-z0-9_.-]{1,62}$'),
 region text NOT NULL DEFAULT '',
 payload jsonb NOT NULL,
 fetched_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(account_id,workspace_id) REFERENCES cloud_accounts(id,workspace_id) ON DELETE CASCADE,
 UNIQUE(account_id,service_key,region)
);

CREATE INDEX IF NOT EXISTS service_snapshots_workspace_idx
 ON service_snapshots(workspace_id,service_key,fetched_at DESC);

COMMENT ON TABLE service_snapshots IS 'Last successful live provider response saved whenever a service page is fetched.';
