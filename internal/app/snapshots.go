package app

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

func (a *App) saveServiceSnapshot(ctx context.Context, workspaceID, accountID int64, service, region string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = a.DB.Exec(ctx, `INSERT INTO service_snapshots(workspace_id,account_id,service_key,region,payload) VALUES($1,$2,$3,$4,$5) ON CONFLICT(account_id,service_key,region) DO UPDATE SET payload=excluded.payload,fetched_at=now()`, workspaceID, accountID, service, region, raw)
	return err
}

func (a *App) serviceSnapshot(ctx context.Context, workspaceID, accountID int64, service, region string) (map[string]any, bool, error) {
	var raw []byte
	var fetchedAt time.Time
	err := a.DB.QueryRow(ctx, `SELECT payload,fetched_at FROM service_snapshots WHERE workspace_id=$1 AND account_id=$2 AND service_key=$3 AND region=$4`, workspaceID, accountID, service, region).Scan(&raw, &fetchedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return map[string]any{"data": []any{}, "snapshot": false, "fetched_at": nil}, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	payload := map[string]any{}
	if err = json.Unmarshal(raw, &payload); err != nil {
		return nil, false, err
	}
	payload["snapshot"], payload["fetched_at"] = true, fetchedAt
	return payload, true, nil
}
