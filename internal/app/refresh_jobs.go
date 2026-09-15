package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/netriun/nexus/internal/secure"
)

const refreshJobTTL = time.Hour

type refreshFailure struct {
	ID      int64  `json:"id"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

type inventoryRefreshJob struct {
	ID             string           `json:"id"`
	WorkspaceID    int64            `json:"-"`
	RequestedBy    int64            `json:"-"`
	RequestedName  string           `json:"-"`
	AccountIDs     []int64          `json:"account_ids"`
	Status         string           `json:"status"`
	CreatedAt      time.Time        `json:"created_at"`
	StartedAt      *time.Time       `json:"started_at,omitempty"`
	CompletedAt    *time.Time       `json:"completed_at,omitempty"`
	DurationMS     int64            `json:"duration_ms,omitempty"`
	FailedAccounts []refreshFailure `json:"failed_accounts"`
	Error          string           `json:"error,omitempty"`
}

func refreshJobKey(workspaceID int64, jobID string) string {
	return fmt.Sprintf("inventory:job:%d:%s", workspaceID, jobID)
}

func refreshScopeKey(workspaceID int64, accountIDs []int64) string {
	ids := slices.Clone(accountIDs)
	slices.Sort(ids)
	parts := make([]string, len(ids))
	for index, id := range ids {
		parts[index] = strconv.FormatInt(id, 10)
	}
	return fmt.Sprintf("inventory:scope:%d:%s", workspaceID, strings.Join(parts, ","))
}

func validRefreshJobID(value string) bool {
	if len(value) < 20 || len(value) > 100 {
		return false
	}
	for _, r := range value {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func (a *App) saveRefreshJob(ctx context.Context, job inventoryRefreshJob) error {
	raw, err := json.Marshal(job)
	if err != nil {
		return err
	}
	return a.Redis.Set(ctx, refreshJobKey(job.WorkspaceID, job.ID), raw, refreshJobTTL).Err()
}

func (a *App) loadRefreshJob(ctx context.Context, workspaceID int64, jobID string) (inventoryRefreshJob, error) {
	var job inventoryRefreshJob
	raw, err := a.Redis.Get(ctx, refreshJobKey(workspaceID, jobID)).Bytes()
	if err != nil {
		return job, err
	}
	err = json.Unmarshal(raw, &job)
	return job, err
}

func (a *App) failedRefreshAccounts(ctx context.Context, workspaceID int64, accountIDs []int64) ([]refreshFailure, error) {
	rows, err := a.DB.Query(ctx, `SELECT id,sync_error,sync_error_code FROM cloud_accounts WHERE workspace_id=$1 AND id=ANY($2) AND sync_error<>'' ORDER BY id`, workspaceID, accountIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	failed := []refreshFailure{}
	for rows.Next() {
		var item refreshFailure
		if err = rows.Scan(&item.ID, &item.Message, &item.Code); err != nil {
			return nil, err
		}
		failed = append(failed, item)
	}
	return failed, rows.Err()
}

// refreshInventory queues provider work and returns immediately. The latest
// database snapshot remains readable while the background job is running.
func (a *App) refreshInventory(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	allowed, err := a.Policy.AccessibleAccountIDs(r.Context(), u, CapabilityAccountView)
	if err != nil {
		dbError(w, err)
		return
	}
	ids, ok := a.requestedAccountIDs(w, r, allowed)
	if !ok {
		return
	}
	if len(ids) == 0 {
		write(w, http.StatusOK, inventoryRefreshJob{Status: "current", AccountIDs: []int64{}, FailedAccounts: []refreshFailure{}})
		return
	}

	scopeKey := refreshScopeKey(u.WorkspaceID, ids)
	if existingID, getErr := a.Redis.Get(r.Context(), scopeKey).Result(); getErr == nil {
		if existing, loadErr := a.loadRefreshJob(r.Context(), u.WorkspaceID, existingID); loadErr == nil && (existing.Status == "queued" || existing.Status == "running") {
			write(w, http.StatusAccepted, existing)
			return
		}
		_, _ = a.Redis.Eval(r.Context(), `if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end`, []string{scopeKey}, existingID).Result()
	}

	job := inventoryRefreshJob{ID: secure.Token(), WorkspaceID: u.WorkspaceID, RequestedBy: u.ID, RequestedName: u.Username, AccountIDs: slices.Clone(ids), Status: "queued", CreatedAt: time.Now().UTC(), FailedAccounts: []refreshFailure{}}
	raw, err := json.Marshal(job)
	if err != nil {
		problem(w, http.StatusServiceUnavailable, "Could not queue live refresh")
		return
	}
	claimedID, err := a.Redis.Eval(r.Context(), `
local existing=redis.call('GET',KEYS[1])
if existing then return existing end
redis.call('SET',KEYS[1],ARGV[1],'EX',600)
redis.call('SET',KEYS[2],ARGV[2],'EX',3600)
return ARGV[1]`, []string{scopeKey, refreshJobKey(job.WorkspaceID, job.ID)}, job.ID, raw).Text()
	if err != nil {
		problem(w, http.StatusServiceUnavailable, "Could not queue live refresh")
		return
	}
	if claimedID != job.ID {
		existing, loadErr := a.loadRefreshJob(r.Context(), u.WorkspaceID, claimedID)
		if loadErr != nil {
			problem(w, http.StatusConflict, "A live refresh is already being queued")
			return
		}
		write(w, http.StatusAccepted, existing)
		return
	}
	a.audit(r, "inventory.refresh_queued", job.ID, map[string]any{"account_ids": ids})
	a.backgroundWG.Add(1)
	go a.runInventoryRefresh(job, scopeKey)
	write(w, http.StatusAccepted, job)
}

func (a *App) runInventoryRefresh(job inventoryRefreshJob, scopeKey string) {
	defer a.backgroundWG.Done()
	ctx, cancel := context.WithTimeout(a.backgroundCtx, 10*time.Minute)
	defer cancel()
	started := time.Now().UTC()
	job.Status, job.StartedAt = "running", &started
	_ = a.saveRefreshJob(ctx, job)

	err := a.refreshRunner(ctx, job.WorkspaceID, job.AccountIDs)
	completed := time.Now().UTC()
	job.CompletedAt = &completed
	job.DurationMS = completed.Sub(started).Milliseconds()
	if err != nil {
		job.Status = "failed"
		job.Error = err.Error()
	} else if job.FailedAccounts, err = a.failedRefreshAccounts(ctx, job.WorkspaceID, job.AccountIDs); err != nil {
		job.Status = "failed"
		job.Error = "Could not read refresh results"
	} else if len(job.FailedAccounts) > 0 {
		job.Status = "partial"
	} else {
		job.Status = "completed"
	}
	slog.Info("inventory refresh finished", "workspace_id", job.WorkspaceID, "job_id", job.ID, "status", job.Status, "accounts", len(job.AccountIDs), "duration_ms", job.DurationMS)
	saveCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	_ = a.saveRefreshJob(saveCtx, job)
	_, _ = a.Redis.Eval(saveCtx, `if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end`, []string{scopeKey}, job.ID).Result()
	_ = a.record(saveCtx, job.WorkspaceID, job.RequestedBy, job.RequestedName, "inventory.refresh_completed", job.ID, map[string]any{"status": job.Status, "duration_ms": job.DurationMS, "account_ids": job.AccountIDs})
}

func (a *App) inventoryRefreshStatus(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("jobID")
	if !validRefreshJobID(jobID) {
		problem(w, http.StatusBadRequest, "Invalid refresh job ID")
		return
	}
	u := current(r)
	job, err := a.loadRefreshJob(r.Context(), u.WorkspaceID, jobID)
	if err != nil {
		problem(w, http.StatusNotFound, "Refresh job not found")
		return
	}
	allowed, err := a.Policy.AccessibleAccountIDs(r.Context(), u, CapabilityAccountView)
	if err != nil {
		dbError(w, err)
		return
	}
	for _, id := range job.AccountIDs {
		if !slices.Contains(allowed, id) {
			problem(w, http.StatusForbidden, "Cloud account access required")
			return
		}
	}
	write(w, http.StatusOK, job)
}
