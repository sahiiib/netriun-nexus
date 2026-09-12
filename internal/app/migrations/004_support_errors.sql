ALTER TABLE cloud_accounts ADD COLUMN IF NOT EXISTS sync_error_code text NOT NULL DEFAULT '';
