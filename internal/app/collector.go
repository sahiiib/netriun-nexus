package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/netriun/nexus/internal/cloud"
	"github.com/netriun/nexus/internal/secure"
)

func (a *App) Collect(parent context.Context, workspaceID int64) error {
	return a.collectAccounts(parent, workspaceID, nil)
}

func (a *App) collectAccounts(parent context.Context, workspaceID int64, accountIDs []int64) error {
	ctx, cancel := context.WithTimeout(parent, 30*time.Minute)
	defer cancel()
	rows, err := a.DB.Query(ctx, "SELECT id,provider,regions FROM cloud_accounts WHERE workspace_id=$1 AND provider IN ('aws','alibaba','azure','gcp') AND ($2::bigint[] IS NULL OR id=ANY($2)) ORDER BY id", workspaceID, accountIDs)
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
	results := make(chan error, len(accounts))
	var wg sync.WaitGroup
	for _, ac := range accounts {
		ac := ac
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- a.withAccountCollectorLock(ctx, workspaceID, ac.id, func(accountCtx context.Context) error {
				select {
				case a.accountSlots <- struct{}{}:
				case <-accountCtx.Done():
					return accountCtx.Err()
				}
				defer func() { <-a.accountSlots }()
				return a.collectAccount(accountCtx, workspaceID, ac.id, ac.provider, ac.regions, a.regionSlots)
			})
		}()
	}
	wg.Wait()
	close(results)
	failures := 0
	for accountErr := range results {
		if accountErr != nil {
			failures++
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

func (a *App) collectAccount(ctx context.Context, workspaceID, accountID int64, provider string, regions []string, regionLimit chan struct{}) error {
	started := time.Now()
	var accountErr error
	if provider == "azure" || provider == "gcp" {
		accountErr = a.collectGlobal(ctx, workspaceID, accountID, provider, regions)
	} else {
		if len(regions) == 0 {
			regionCtx, stop := context.WithTimeout(ctx, 60*time.Second)
			if provider == "aws" {
				client, clientErr := a.awsClient(regionCtx, workspaceID, accountID, "us-east-1")
				if clientErr != nil {
					accountErr = clientErr
				} else {
					regions, accountErr = cloud.Regions(regionCtx, client)
				}
			} else {
				client, clientErr := a.alibabaClient(regionCtx, workspaceID, accountID, "cn-hangzhou")
				if clientErr != nil {
					accountErr = clientErr
				} else {
					regions, accountErr = cloud.AlibabaRegions(regionCtx, client)
				}
			}
			stop()
		}
		if accountErr == nil {
			errorsByRegion := make(chan error, len(regions))
			var wg sync.WaitGroup
			for _, region := range regions {
				region := region
				wg.Add(1)
				go func() {
					defer wg.Done()
					select {
					case regionLimit <- struct{}{}:
					case <-ctx.Done():
						errorsByRegion <- ctx.Err()
						return
					}
					defer func() { <-regionLimit }()
					if err := a.collectRegion(ctx, workspaceID, accountID, provider, region); err != nil {
						errorsByRegion <- fmt.Errorf("region %s: %w", region, err)
					}
				}()
			}
			wg.Wait()
			close(errorsByRegion)
			for regionErr := range errorsByRegion {
				accountErr = errors.Join(accountErr, regionErr)
			}
		}
	}
	if accountErr != nil {
		slog.Warn("cloud collection failed", "provider", provider, "account_id", accountID, "duration_ms", time.Since(started).Milliseconds(), "error", accountErr)
		_, _ = a.DB.Exec(ctx, "UPDATE cloud_accounts SET sync_error=$1,sync_error_code=$2 WHERE id=$3", "Collection failed. Check credentials, permissions and selected regions.", providerErrorCode(provider), accountID)
		_ = a.record(ctx, workspaceID, 0, "system", "collector.account_failed", strconv.FormatInt(accountID, 10), nil)
		return accountErr
	}
	_, err := a.DB.Exec(ctx, "UPDATE cloud_accounts SET last_sync_at=now(),sync_error='',sync_error_code='' WHERE id=$1", accountID)
	if err == nil {
		slog.Info("cloud collection completed", "provider", provider, "account_id", accountID, "duration_ms", time.Since(started).Milliseconds())
	}
	return err
}

func (a *App) withAccountCollectorLock(ctx context.Context, workspaceID, accountID int64, collect func(context.Context) error) error {
	key := fmt.Sprintf("collector:lock:%d:compute:%d", workspaceID, accountID)
	waitStarted := time.Now()
	token := secure.Token()
	locked, err := a.Redis.SetNX(ctx, key, token, 2*time.Minute).Result()
	if err != nil {
		return err
	}
	if !locked {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			exists, existsErr := a.Redis.Exists(ctx, key).Result()
			if existsErr != nil {
				return existsErr
			}
			if exists == 0 {
				var refreshed bool
				if queryErr := a.DB.QueryRow(ctx, "SELECT COALESCE(last_sync_at>$1,false) FROM cloud_accounts WHERE workspace_id=$2 AND id=$3", waitStarted, workspaceID, accountID).Scan(&refreshed); queryErr != nil {
					return queryErr
				}
				if refreshed {
					return nil
				}
				return a.withAccountCollectorLock(ctx, workspaceID, accountID, collect)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	}
	accountCtx, stopAccount := context.WithCancel(ctx)
	defer stopAccount()
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-accountCtx.Done():
				return
			case <-ticker.C:
				if renewed, renewErr := a.Redis.Eval(accountCtx, `if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('EXPIRE',KEYS[1],ARGV[2]) else return 0 end`, []string{key}, token, 120).Int(); renewErr != nil || renewed != 1 {
					stopAccount()
					return
				}
			}
		}
	}()
	defer func() {
		releaseCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		_, _ = a.Redis.Eval(releaseCtx, `if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end`, []string{key}, token).Result()
	}()
	return collect(accountCtx)
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
	ids := make([]string, 0, len(items))
	itemRegions := make([]string, 0, len(items))
	names := make([]string, 0, len(items))
	states := make([]string, 0, len(items))
	types := make([]string, 0, len(items))
	publicIPs := make([]string, 0, len(items))
	privateIPs := make([]string, 0, len(items))
	details := make([]string, 0, len(items))
	for _, i := range items {
		if i.Region == "" {
			return errors.New("provider returned an instance without a region")
		}
		ids = append(ids, i.ID)
		b, _ := json.Marshal(i.Details)
		itemRegions = append(itemRegions, i.Region)
		names = append(names, i.Name)
		states = append(states, i.State)
		types = append(types, i.Type)
		publicIPs = append(publicIPs, i.PublicIP)
		privateIPs = append(privateIPs, i.PrivateIP)
		details = append(details, string(b))
	}
	if len(items) > 0 {
		_, err = tx.Exec(ctx, `
INSERT INTO instances(account_id,instance_id,region,name,state,instance_type,public_ip,private_ip,details)
SELECT $1,item.id,item.region,item.name,item.state,item.instance_type,item.public_ip,item.private_ip,item.details::jsonb
FROM unnest($2::text[],$3::text[],$4::text[],$5::text[],$6::text[],$7::text[],$8::text[],$9::text[])
 AS item(id,region,name,state,instance_type,public_ip,private_ip,details)
ON CONFLICT(account_id,region,instance_id) DO UPDATE SET
 name=excluded.name,state=excluded.state,instance_type=excluded.instance_type,
 public_ip=excluded.public_ip,private_ip=excluded.private_ip,details=excluded.details,seen_at=now()`,
			accountID, ids, itemRegions, names, states, types, publicIPs, privateIPs, details)
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
