package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/netriun/nexus/internal/cloud"
	"github.com/netriun/nexus/internal/secure"
)

var ossBucketNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

type ossRefreshJob struct {
	ID            string     `json:"id"`
	WorkspaceID   int64      `json:"-"`
	RequestedBy   int64      `json:"-"`
	RequestedName string     `json:"-"`
	AccountID     int64      `json:"account_id"`
	Status        string     `json:"status"`
	CreatedAt     time.Time  `json:"created_at"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	DurationMS    int64      `json:"duration_ms,omitempty"`
	Error         string     `json:"error,omitempty"`
}

func ossRefreshJobKey(workspaceID int64, jobID string) string {
	return fmt.Sprintf("oss:refresh:job:%d:%s", workspaceID, jobID)
}

func ossRefreshScopeKey(workspaceID, accountID int64) string {
	return fmt.Sprintf("oss:refresh:scope:%d:%d", workspaceID, accountID)
}

func (a *App) ossAccount(w http.ResponseWriter, r *http.Request, mode string) (int64, bool) {
	accountID, ok := pathID(w, r, "id")
	if !ok {
		return 0, false
	}
	if !a.accountAccess(r, accountID, mode) {
		problem(w, http.StatusForbidden, "Cloud account access required")
		return 0, false
	}
	var provider string
	if err := a.DB.QueryRow(r.Context(), `SELECT provider FROM cloud_accounts WHERE id=$1 AND workspace_id=$2`, accountID, current(r).WorkspaceID).Scan(&provider); err != nil {
		dbError(w, err)
		return 0, false
	}
	if provider != "alibaba" {
		problem(w, http.StatusBadRequest, "The selected account is not an Alibaba Cloud connection")
		return 0, false
	}
	return accountID, true
}

func (a *App) ossBuckets(w http.ResponseWriter, r *http.Request) {
	accountID, ok := a.ossAccount(w, r, "view")
	if !ok {
		return
	}
	payload, _, err := a.serviceSnapshot(r.Context(), current(r).WorkspaceID, accountID, "oss.buckets", "")
	if err != nil {
		dbError(w, err)
		return
	}
	write(w, http.StatusOK, payload)
}

func (a *App) saveOSSRefreshJob(ctx context.Context, job ossRefreshJob) error {
	raw, err := json.Marshal(job)
	if err != nil {
		return err
	}
	return a.Redis.Set(ctx, ossRefreshJobKey(job.WorkspaceID, job.ID), raw, refreshJobTTL).Err()
}

func (a *App) loadOSSRefreshJob(ctx context.Context, workspaceID int64, jobID string) (ossRefreshJob, error) {
	var job ossRefreshJob
	raw, err := a.Redis.Get(ctx, ossRefreshJobKey(workspaceID, jobID)).Bytes()
	if err != nil {
		return job, err
	}
	err = json.Unmarshal(raw, &job)
	return job, err
}

func (a *App) refreshOSS(w http.ResponseWriter, r *http.Request) {
	accountID, ok := a.ossAccount(w, r, "view")
	if !ok {
		return
	}
	u := current(r)
	scopeKey := ossRefreshScopeKey(u.WorkspaceID, accountID)
	if existingID, err := a.Redis.Get(r.Context(), scopeKey).Result(); err == nil {
		if existing, loadErr := a.loadOSSRefreshJob(r.Context(), u.WorkspaceID, existingID); loadErr == nil && (existing.Status == "queued" || existing.Status == "running") {
			write(w, http.StatusAccepted, existing)
			return
		}
	}
	job := ossRefreshJob{ID: secure.Token(), WorkspaceID: u.WorkspaceID, RequestedBy: u.ID, RequestedName: u.Username, AccountID: accountID, Status: "queued", CreatedAt: time.Now().UTC()}
	raw, err := json.Marshal(job)
	if err != nil {
		problem(w, http.StatusServiceUnavailable, "Could not queue OSS refresh")
		return
	}
	claimedID, err := a.Redis.Eval(r.Context(), `local existing=redis.call('GET',KEYS[1]); if existing then return existing end; redis.call('SET',KEYS[1],ARGV[1],'EX',600); redis.call('SET',KEYS[2],ARGV[2],'EX',3600); return ARGV[1]`, []string{scopeKey, ossRefreshJobKey(u.WorkspaceID, job.ID)}, job.ID, raw).Text()
	if err != nil {
		problem(w, http.StatusServiceUnavailable, "Could not queue OSS refresh")
		return
	}
	if claimedID != job.ID {
		existing, loadErr := a.loadOSSRefreshJob(r.Context(), u.WorkspaceID, claimedID)
		if loadErr != nil {
			problem(w, http.StatusConflict, "An OSS refresh is already being queued")
			return
		}
		write(w, http.StatusAccepted, existing)
		return
	}
	a.audit(r, "oss.refresh_queued", job.ID, map[string]any{"account_id": accountID})
	a.backgroundWG.Add(1)
	go a.runOSSRefresh(job, scopeKey)
	write(w, http.StatusAccepted, job)
}

func (a *App) runOSSRefresh(job ossRefreshJob, scopeKey string) {
	defer a.backgroundWG.Done()
	ctx, cancel := context.WithTimeout(a.backgroundCtx, 5*time.Minute)
	defer cancel()
	started := time.Now().UTC()
	job.Status, job.StartedAt = "running", &started
	_ = a.saveOSSRefreshJob(ctx, job)
	err := a.withServiceCollectorLock(ctx, job.WorkspaceID, job.AccountID, "oss", func(lockCtx context.Context) error {
		return a.ossRefreshRunner(lockCtx, job.WorkspaceID, job.AccountID)
	})
	completed := time.Now().UTC()
	job.CompletedAt, job.DurationMS = &completed, completed.Sub(started).Milliseconds()
	if err != nil {
		job.Status, job.Error = "failed", "Alibaba OSS refresh failed; check RAM permissions and account access"
		slog.Warn("Alibaba OSS refresh failed", "workspace_id", job.WorkspaceID, "account_id", job.AccountID, "error", err)
	} else {
		job.Status = "completed"
	}
	saveCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	_ = a.saveOSSRefreshJob(saveCtx, job)
	_, _ = a.Redis.Eval(saveCtx, `if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end`, []string{scopeKey}, job.ID).Result()
	_ = a.record(saveCtx, job.WorkspaceID, job.RequestedBy, job.RequestedName, "oss.refresh_completed", job.ID, map[string]any{"status": job.Status, "duration_ms": job.DurationMS, "account_id": job.AccountID})
}

func (a *App) ossRefreshStatus(w http.ResponseWriter, r *http.Request) {
	accountID, ok := a.ossAccount(w, r, "view")
	if !ok {
		return
	}
	jobID := r.PathValue("jobID")
	if !validRefreshJobID(jobID) {
		problem(w, http.StatusBadRequest, "Invalid refresh job ID")
		return
	}
	job, err := a.loadOSSRefreshJob(r.Context(), current(r).WorkspaceID, jobID)
	if err != nil || job.AccountID != accountID {
		problem(w, http.StatusNotFound, "Refresh job not found")
		return
	}
	write(w, http.StatusOK, job)
}

func (a *App) collectOSSBuckets(ctx context.Context, workspaceID, accountID int64) error {
	credentials, err := a.credentials(ctx, workspaceID, accountID, "alibaba")
	if err != nil {
		return err
	}
	seedRegion := "cn-hangzhou"
	if err = a.DB.QueryRow(ctx, `SELECT COALESCE(NULLIF(regions[1],''),'cn-hangzhou') FROM cloud_accounts WHERE id=$1 AND workspace_id=$2`, accountID, workspaceID).Scan(&seedRegion); err != nil {
		return err
	}
	items, err := cloud.OSSListBuckets(ctx, cloud.OSSClient(seedRegion, credentials.AccessKey, credentials.SecretKey, credentials.SessionToken))
	if err != nil {
		return err
	}
	failed := []string{}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for index := range items {
		index := index
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case a.regionSlots <- struct{}{}:
			case <-ctx.Done():
				mu.Lock()
				failed = append(failed, items[index].Name)
				mu.Unlock()
				return
			}
			defer func() { <-a.regionSlots }()
			client := cloud.OSSClient(items[index].Region, credentials.AccessKey, credentials.SecretKey, credentials.SessionToken)
			detailErr := cloud.OSSBucketDetails(ctx, client, &items[index])
			statErr := cloud.OSSBucketStats(ctx, client, &items[index])
			if detailErr == nil && statErr == nil {
				items[index].Status = "available"
				return
			}
			items[index].Status = "partial"
			mu.Lock()
			failed = append(failed, items[index].Name)
			mu.Unlock()
			slog.Warn("Alibaba OSS bucket details partially unavailable", "account_id", accountID, "bucket", items[index].Name, "details_error", detailErr, "stats_error", statErr)
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	sort.Strings(failed)
	return a.saveServiceSnapshot(ctx, workspaceID, accountID, "oss.buckets", "", map[string]any{"data": items, "failed_buckets": failed})
}

func (a *App) createOSSBucket(w http.ResponseWriter, r *http.Request) {
	accountID, ok := a.ossAccount(w, r, "manage")
	if !ok {
		return
	}
	var in struct {
		Name           string `json:"name"`
		Region         string `json:"region"`
		StorageClass   string `json:"storage_class"`
		RedundancyType string `json:"redundancy_type"`
		ConfirmCost    bool   `json:"confirm_cost"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name, in.Region = strings.TrimSpace(in.Name), strings.TrimSpace(in.Region)
	if !ossBucketNamePattern.MatchString(in.Name) {
		problem(w, http.StatusBadRequest, "Bucket name must be 3–63 lowercase letters, numbers, or hyphens and must start and end with a letter or number")
		return
	}
	if !regionPattern.MatchString(in.Region) {
		problem(w, http.StatusBadRequest, "A valid Alibaba Cloud region is required")
		return
	}
	if in.StorageClass != "Standard" && in.StorageClass != "IA" && in.StorageClass != "Archive" && in.StorageClass != "ColdArchive" {
		problem(w, http.StatusBadRequest, "Unsupported OSS storage class")
		return
	}
	if in.RedundancyType != "LRS" && in.RedundancyType != "ZRS" {
		problem(w, http.StatusBadRequest, "OSS redundancy must be LRS or ZRS")
		return
	}
	if !in.ConfirmCost {
		problem(w, http.StatusBadRequest, "Explicit cost confirmation is required")
		return
	}
	u := current(r)
	if err := a.record(r.Context(), u.WorkspaceID, u.ID, u.Username, "oss.bucket.create.requested", in.Name, map[string]any{"account_id": accountID, "region": in.Region, "storage_class": in.StorageClass, "redundancy_type": in.RedundancyType, "acl": "private"}); err != nil {
		problem(w, http.StatusServiceUnavailable, "Bucket was not submitted because audit storage is unavailable")
		return
	}
	credentials, err := a.credentials(r.Context(), u.WorkspaceID, accountID, "alibaba")
	if err != nil {
		problem(w, http.StatusBadRequest, "The selected account is not an Alibaba Cloud connection")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	err = cloud.OSSCreateBucket(ctx, cloud.OSSClient(in.Region, credentials.AccessKey, credentials.SecretKey, credentials.SessionToken), cloud.OSSCreateBucketInput{Name: in.Name, Region: in.Region, StorageClass: in.StorageClass, RedundancyType: in.RedundancyType})
	if err != nil {
		a.audit(r, "oss.bucket.create.failed", in.Name, nil)
		slog.Warn("Alibaba OSS bucket creation failed", "account_id", accountID, "bucket", in.Name, "region", in.Region, "error", err)
		problem(w, http.StatusBadGateway, "Alibaba OSS rejected bucket creation; check global name availability, region support, RAM permissions, and account activation")
		return
	}
	a.audit(r, "oss.bucket.create.accepted", in.Name, nil)
	write(w, http.StatusAccepted, map[string]string{"status": "created", "name": in.Name, "region": in.Region})
}
