package app

import (
	"context"
	"encoding/json"
)

func (a *App) saveServiceSnapshot(ctx context.Context, workspaceID, accountID int64, service, region string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = a.DB.Exec(ctx, `INSERT INTO service_snapshots(workspace_id,account_id,service_key,region,payload) VALUES($1,$2,$3,$4,$5) ON CONFLICT(account_id,service_key,region) DO UPDATE SET payload=excluded.payload,fetched_at=now()`, workspaceID, accountID, service, region, raw)
	return err
}
