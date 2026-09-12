package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/netriun/nexus/internal/cloud"
	"github.com/netriun/nexus/internal/secure"
)

// Scheduler uses a durable Redis request flag and a renewable distributed lease.
func (a *App) Scheduler(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rows, err := a.DB.Query(ctx, "SELECT workspace_id,last_collector_run_at IS NULL OR last_collector_run_at < now()-make_interval(mins=>collector_interval_minutes) FROM settings ORDER BY workspace_id")
			if err != nil {
				continue
			}
			type workspace struct {
				id  int64
				due bool
			}
			var workspaces []workspace
			for rows.Next() {
				var ws workspace
				if rows.Scan(&ws.id, &ws.due) == nil {
					workspaces = append(workspaces, ws)
				}
			}
			rows.Close()
			for _, ws := range workspaces {
				requested, redisErr := a.Redis.Exists(ctx, collectorKey("requested", ws.id)).Result()
				if redisErr == nil && (ws.due || requested > 0) {
					if err = a.Collect(ctx, ws.id); err != nil {
						slog.Error("collection failed", "workspace_id", ws.id, "error", err)
					}
				}
			}
		}
	}
}
func (a *App) triggerCollector(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	if err := a.Redis.Set(r.Context(), collectorKey("requested", current(r).WorkspaceID), "1", 0).Err(); err != nil {
		problem(w, 503, "Collector unavailable")
		return
	}
	a.audit(r, "collector.requested", "", nil)
	write(w, 202, map[string]string{"status": "queued"})
}
func collectorKey(kind string, workspaceID int64) string {
	return fmt.Sprintf("collector:%s:%d", kind, workspaceID)
}

func (a *App) Collect(parent context.Context, workspaceID int64) error {
	token := secure.Token()
	lockKey := collectorKey("lock", workspaceID)
	locked, err := a.Redis.SetNX(parent, lockKey, token, 60*time.Second).Result()
	if err != nil || !locked {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Minute)
	defer cancel()
	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				n, e := a.Redis.Eval(ctx, `if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('EXPIRE',KEYS[1],60) else return 0 end`, []string{lockKey}, token).Int()
				if e != nil || n != 1 {
					cancel()
					return
				}
			}
		}
	}()
	defer func() {
		release, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		a.Redis.Eval(release, `if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end`, []string{lockKey}, token)
	}()
	if err = a.Redis.Del(ctx, collectorKey("requested", workspaceID)).Err(); err != nil {
		return err
	}
	rows, err := a.DB.Query(ctx, "SELECT id,provider,regions FROM cloud_accounts WHERE workspace_id=$1 AND provider IN ('aws','alibaba','azure','gcp') ORDER BY id", workspaceID)
	if err != nil {
		return err
	}
	type account struct {
		id       int64
		provider string
		regions  []string
	}
	accounts := []account{}
	for rows.Next() {
		var ac account
		if err = rows.Scan(&ac.id, &ac.provider, &ac.regions); err != nil {
			rows.Close()
			return err
		}
		accounts = append(accounts, ac)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	failures := 0
	for _, ac := range accounts {
		regions := ac.regions
		var accountErr error
		if ac.provider == "azure" || ac.provider == "gcp" {
			accountErr = a.collectGlobal(ctx, workspaceID, ac.id, ac.provider, regions)
			if accountErr != nil {
				failures++
				slog.Warn("cloud collection failed", "provider", ac.provider, "account_id", ac.id, "error", accountErr)
				a.DB.Exec(ctx, "UPDATE cloud_accounts SET sync_error=$1,sync_error_code=$2 WHERE id=$3", "Collection failed. Check credentials, permissions and selected regions.", providerErrorCode(ac.provider), ac.id)
				a.record(ctx, workspaceID, 0, "system", "collector.account_failed", fmt.Sprint(ac.id), nil)
			} else {
				a.DB.Exec(ctx, "UPDATE cloud_accounts SET last_sync_at=now(),sync_error='',sync_error_code='' WHERE id=$1", ac.id)
			}
			continue
		}
		if len(regions) == 0 {
			regionCtx, stop := context.WithTimeout(ctx, 60*time.Second)
			if ac.provider == "aws" {
				c, e := a.awsClient(regionCtx, workspaceID, ac.id, "us-east-1")
				if e != nil {
					accountErr = e
				} else {
					regions, accountErr = cloud.Regions(regionCtx, c)
				}
			} else {
				c, e := a.alibabaClient(regionCtx, workspaceID, ac.id, "cn-hangzhou")
				if e != nil {
					accountErr = e
				} else {
					regions, accountErr = cloud.AlibabaRegions(regionCtx, c)
				}
			}
			stop()
		}
		if accountErr == nil {
			for _, region := range regions {
				if e := a.collectRegion(ctx, workspaceID, ac.id, ac.provider, region); e != nil {
					accountErr = errors.Join(accountErr, fmt.Errorf("region %s: %w", region, e))
				}
			}
		}
		if accountErr != nil {
			failures++
			slog.Warn("cloud collection failed", "provider", ac.provider, "account_id", ac.id, "error", accountErr)
			a.DB.Exec(ctx, "UPDATE cloud_accounts SET sync_error=$1,sync_error_code=$2 WHERE id=$3", "Collection failed. Check credentials, permissions and selected regions.", providerErrorCode(ac.provider), ac.id)
			a.record(ctx, workspaceID, 0, "system", "collector.account_failed", fmt.Sprint(ac.id), nil)
		} else {
			a.DB.Exec(ctx, "UPDATE cloud_accounts SET last_sync_at=now(),sync_error='',sync_error_code='' WHERE id=$1", ac.id)
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if _, err = a.DB.Exec(ctx, "UPDATE settings SET last_collector_run_at=now() WHERE workspace_id=$1", workspaceID); err != nil {
		return err
	}
	a.record(ctx, workspaceID, 0, "system", "collector.completed", "", map[string]int{"accounts": len(accounts), "failed_accounts": failures})
	_, err = a.DB.Exec(ctx, "DELETE FROM audit_log WHERE workspace_id=$1 AND created_at < now()-make_interval(days=>(SELECT audit_retention_days FROM settings WHERE workspace_id=$1))", workspaceID)
	return err
}

// Azure and GCP expose subscription/project-wide compute inventory endpoints.
// Fetching once avoids duplicating every VM for each configured region.
func (a *App) collectGlobal(ctx context.Context, workspaceID, accountID int64, provider string, regions []string) error {
	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	var items []cloud.Instance
	var err error
	switch provider {
	case "azure":
		var client *cloud.AzureClient
		client, err = a.azureClient(requestCtx, workspaceID, accountID)
		if err == nil {
			items, err = cloud.AzureInventory(requestCtx, client)
		}
	case "gcp":
		var client *cloud.GCPClient
		client, err = a.gcpClient(requestCtx, workspaceID, accountID)
		if err == nil {
			items, err = cloud.GCPInventory(requestCtx, client)
		}
	default:
		return fmt.Errorf("unsupported global provider %q", provider)
	}
	if err != nil {
		return err
	}
	if len(regions) > 0 {
		items = slices.DeleteFunc(items, func(item cloud.Instance) bool { return !slices.Contains(regions, item.Region) })
	}
	return a.reconcileInventory(requestCtx, accountID, items, true, "")
}

func (a *App) collectRegion(ctx context.Context, workspaceID, accountID int64, provider, region string) error {
	regionCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var items []cloud.Instance
	var err error
	if provider == "aws" {
		c, clientErr := a.awsClient(regionCtx, workspaceID, accountID, region)
		err = clientErr
		if err == nil {
			items, err = cloud.Inventory(regionCtx, c)
		}
	} else if provider == "alibaba" {
		c, clientErr := a.alibabaClient(regionCtx, workspaceID, accountID, region)
		err = clientErr
		if err == nil {
			items, err = cloud.AlibabaInventory(regionCtx, c, region)
		}
	} else {
		return fmt.Errorf("unsupported provider %q", provider)
	}
	if err != nil {
		return err
	}
	for index := range items {
		items[index].Region = region
	}
	return a.reconcileInventory(regionCtx, accountID, items, false, region)
}

func (a *App) reconcileInventory(ctx context.Context, accountID int64, items []cloud.Instance, wholeAccount bool, region string) error {
	// Reconcile only after every provider page succeeded; failed regions retain their inventory.
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	ids := []string{}
	for _, i := range items {
		if i.Region == "" {
			return errors.New("provider returned an instance without a region")
		}
		ids = append(ids, i.ID)
		b, _ := json.Marshal(i.Details)
		_, err = tx.Exec(ctx, `INSERT INTO instances(account_id,instance_id,region,name,state,instance_type,public_ip,private_ip,details) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(account_id,region,instance_id) DO UPDATE SET name=excluded.name,state=excluded.state,instance_type=excluded.instance_type,public_ip=excluded.public_ip,private_ip=excluded.private_ip,details=excluded.details,seen_at=now()`, accountID, i.ID, i.Region, i.Name, i.State, i.Type, i.PublicIP, i.PrivateIP, b)
		if err != nil {
			return err
		}
	}
	if wholeAccount {
		_, err = tx.Exec(ctx, "DELETE FROM instances WHERE account_id=$1 AND NOT(instance_id=ANY($2::text[]))", accountID, ids)
	} else {
		_, err = tx.Exec(ctx, "DELETE FROM instances WHERE account_id=$1 AND region=$2 AND NOT(instance_id=ANY($3::text[]))", accountID, region, ids)
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
