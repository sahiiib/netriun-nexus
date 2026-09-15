package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/netriun/nexus/internal/cloud"
	"github.com/netriun/nexus/internal/secure"
)

type edsRegionCount struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Desktops  int    `json:"desktops"`
	Available bool   `json:"available"`
}

type edsRegionResponse struct {
	Data          []edsRegionCount `json:"data"`
	TotalDesktops int              `json:"total_desktops"`
}

type edsRefreshJob struct {
	ID            string     `json:"id"`
	WorkspaceID   int64      `json:"-"`
	RequestedBy   int64      `json:"-"`
	RequestedName string     `json:"-"`
	AccountID     int64      `json:"account_id"`
	Service       string     `json:"service"`
	Region        string     `json:"region"`
	Status        string     `json:"status"`
	CreatedAt     time.Time  `json:"created_at"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	DurationMS    int64      `json:"duration_ms,omitempty"`
	Error         string     `json:"error,omitempty"`
}

func edsRefreshJobKey(workspaceID int64, jobID string) string {
	return fmt.Sprintf("eds:refresh:job:%d:%s", workspaceID, jobID)
}

func edsRefreshScopeKey(workspaceID, accountID int64, service, region string) string {
	return fmt.Sprintf("eds:refresh:scope:%d:%d:%s:%s", workspaceID, accountID, service, region)
}

func (a *App) edsSnapshotAccount(w http.ResponseWriter, r *http.Request, allowAll, requireRegion bool) (int64, string, bool) {
	accountID, ok := pathID(w, r, "id")
	if !ok {
		return 0, "", false
	}
	if !a.accountAccess(r, accountID, "view") {
		problem(w, http.StatusForbidden, "Cloud account access required")
		return 0, "", false
	}
	region := strings.TrimSpace(r.URL.Query().Get("region"))
	if requireRegion && (region == "" || region == "all" && !allowAll || region != "all" && !regionPattern.MatchString(region)) {
		problem(w, http.StatusBadRequest, "A valid Alibaba Cloud region is required")
		return 0, "", false
	}
	var provider string
	if err := a.DB.QueryRow(r.Context(), `SELECT provider FROM cloud_accounts WHERE id=$1 AND workspace_id=$2`, accountID, current(r).WorkspaceID).Scan(&provider); err != nil {
		dbError(w, err)
		return 0, "", false
	}
	if provider != "alibaba" {
		problem(w, http.StatusBadRequest, "The selected account is not an Alibaba Cloud connection")
		return 0, "", false
	}
	return accountID, region, true
}

func (a *App) saveEDSRefreshJob(ctx context.Context, job edsRefreshJob) error {
	raw, err := json.Marshal(job)
	if err != nil {
		return err
	}
	return a.Redis.Set(ctx, edsRefreshJobKey(job.WorkspaceID, job.ID), raw, refreshJobTTL).Err()
}

func (a *App) loadEDSRefreshJob(ctx context.Context, workspaceID int64, jobID string) (edsRefreshJob, error) {
	var job edsRefreshJob
	raw, err := a.Redis.Get(ctx, edsRefreshJobKey(workspaceID, jobID)).Bytes()
	if err != nil {
		return job, err
	}
	err = json.Unmarshal(raw, &job)
	return job, err
}

func (a *App) refreshEDS(w http.ResponseWriter, r *http.Request) {
	accountID, region, ok := a.edsSnapshotAccount(w, r, true, true)
	if !ok {
		return
	}
	service := strings.TrimSpace(r.URL.Query().Get("service"))
	if service != "desktops" && service != "users" {
		problem(w, http.StatusBadRequest, "EDS refresh service must be desktops or users")
		return
	}
	if service == "users" && region == "all" {
		problem(w, http.StatusBadRequest, "EDS users require a directory region")
		return
	}
	u := current(r)
	scopeKey := edsRefreshScopeKey(u.WorkspaceID, accountID, service, region)
	if existingID, err := a.Redis.Get(r.Context(), scopeKey).Result(); err == nil {
		if existing, loadErr := a.loadEDSRefreshJob(r.Context(), u.WorkspaceID, existingID); loadErr == nil && (existing.Status == "queued" || existing.Status == "running") {
			write(w, http.StatusAccepted, existing)
			return
		}
	}
	job := edsRefreshJob{ID: secure.Token(), WorkspaceID: u.WorkspaceID, RequestedBy: u.ID, RequestedName: u.Username, AccountID: accountID, Service: service, Region: region, Status: "queued", CreatedAt: time.Now().UTC()}
	raw, err := json.Marshal(job)
	if err != nil {
		problem(w, 503, "Could not queue EDS refresh")
		return
	}
	claimedID, err := a.Redis.Eval(r.Context(), `local existing=redis.call('GET',KEYS[1]); if existing then return existing end; redis.call('SET',KEYS[1],ARGV[1],'EX',600); redis.call('SET',KEYS[2],ARGV[2],'EX',3600); return ARGV[1]`, []string{scopeKey, edsRefreshJobKey(u.WorkspaceID, job.ID)}, job.ID, raw).Text()
	if err != nil {
		problem(w, 503, "Could not queue EDS refresh")
		return
	}
	if claimedID != job.ID {
		existing, loadErr := a.loadEDSRefreshJob(r.Context(), u.WorkspaceID, claimedID)
		if loadErr != nil {
			problem(w, 409, "An EDS refresh is already being queued")
			return
		}
		write(w, http.StatusAccepted, existing)
		return
	}
	a.audit(r, "eds.refresh_queued", job.ID, map[string]any{"account_id": accountID, "service": service, "region": region})
	a.backgroundWG.Add(1)
	go a.runEDSRefresh(job, scopeKey)
	write(w, http.StatusAccepted, job)
}

func (a *App) runEDSRefresh(job edsRefreshJob, scopeKey string) {
	defer a.backgroundWG.Done()
	ctx, cancel := context.WithTimeout(a.backgroundCtx, 5*time.Minute)
	defer cancel()
	started := time.Now().UTC()
	job.Status, job.StartedAt = "running", &started
	_ = a.saveEDSRefreshJob(ctx, job)
	err := a.edsRefreshRunner(ctx, job.WorkspaceID, job.AccountID, job.Service, job.Region)
	completed := time.Now().UTC()
	job.CompletedAt, job.DurationMS = &completed, completed.Sub(started).Milliseconds()
	if err != nil {
		job.Status, job.Error = "failed", err.Error()
	} else {
		job.Status = "completed"
	}
	saveCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	_ = a.saveEDSRefreshJob(saveCtx, job)
	_, _ = a.Redis.Eval(saveCtx, `if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end`, []string{scopeKey}, job.ID).Result()
	_ = a.record(saveCtx, job.WorkspaceID, job.RequestedBy, job.RequestedName, "eds.refresh_completed", job.ID, map[string]any{"status": job.Status, "duration_ms": job.DurationMS, "account_id": job.AccountID, "service": job.Service, "region": job.Region})
	slog.Info("EDS refresh finished", "workspace_id", job.WorkspaceID, "account_id", job.AccountID, "service", job.Service, "region", job.Region, "status", job.Status, "duration_ms", job.DurationMS)
}

func (a *App) edsRefreshStatus(w http.ResponseWriter, r *http.Request) {
	accountID, _, ok := a.edsSnapshotAccount(w, r, false, false)
	if !ok {
		return
	}
	jobID := r.PathValue("jobID")
	if !validRefreshJobID(jobID) {
		problem(w, 400, "Invalid refresh job ID")
		return
	}
	job, err := a.loadEDSRefreshJob(r.Context(), current(r).WorkspaceID, jobID)
	if err != nil || job.AccountID != accountID {
		problem(w, 404, "Refresh job not found")
		return
	}
	write(w, 200, job)
}

func (a *App) refreshEDSService(ctx context.Context, workspaceID, accountID int64, service, region string) error {
	return a.withServiceCollectorLock(ctx, workspaceID, accountID, "eds", func(lockCtx context.Context) error {
		regions, err := a.collectEDSRegions(lockCtx, workspaceID, accountID)
		if err != nil {
			return err
		}
		if service == "desktops" {
			return a.collectEDSDesktops(lockCtx, workspaceID, accountID, region, regions)
		}
		if service == "users" {
			var usersErr, desktopsErr error
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); usersErr = a.collectEDSUsers(lockCtx, workspaceID, accountID, region) }()
			go func() {
				defer wg.Done()
				desktopsErr = a.collectEDSDesktops(lockCtx, workspaceID, accountID, "all", regions)
			}()
			wg.Wait()
			return errors.Join(usersErr, desktopsErr)
		}
		return errors.New("unsupported EDS service")
	})
}

func (a *App) edsCredentials(ctx context.Context, workspaceID, accountID int64) (Credentials, string, error) {
	credentials, err := a.credentials(ctx, workspaceID, accountID, "alibaba")
	if err != nil {
		return credentials, "", err
	}
	var seedRegion string
	err = a.DB.QueryRow(ctx, `SELECT COALESCE((SELECT min(region) FROM instances WHERE account_id=$1), NULLIF(regions[1],''), 'cn-hangzhou') FROM cloud_accounts WHERE id=$1 AND workspace_id=$2`, accountID, workspaceID).Scan(&seedRegion)
	return credentials, seedRegion, err
}

func (a *App) withServiceCollectorLock(ctx context.Context, workspaceID, accountID int64, service string, collect func(context.Context) error) error {
	key := fmt.Sprintf("collector:lock:%d:%s:%d", workspaceID, service, accountID)
	token := secure.Token()
	for {
		locked, err := a.Redis.SetNX(ctx, key, token, 2*time.Minute).Result()
		if err != nil {
			return err
		}
		if locked {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	accountCtx, cancel := context.WithCancel(ctx)
	defer cancel()
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
				if renewed, err := a.Redis.Eval(accountCtx, `if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('EXPIRE',KEYS[1],ARGV[2]) else return 0 end`, []string{key}, token, 120).Int(); err != nil || renewed != 1 {
					cancel()
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

func (a *App) collectEDSRegions(ctx context.Context, workspaceID, accountID int64) ([]edsRegionCount, error) {
	credentials, seedRegion, err := a.edsCredentials(ctx, workspaceID, accountID)
	if err != nil {
		return nil, err
	}
	seed, err := cloud.EDSClient(seedRegion, credentials.AccessKey, credentials.SecretKey, credentials.SessionToken)
	if err != nil {
		return nil, err
	}
	regions, err := cloud.EDSRegions(ctx, seed.Desktop)
	if err != nil {
		return nil, err
	}
	counts := make([]edsRegionCount, len(regions))
	var wg sync.WaitGroup
	for i, region := range regions {
		counts[i] = edsRegionCount{ID: region.ID, Name: region.Name, Desktops: -1}
		i, region := i, region
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case a.regionSlots <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-a.regionSlots }()
			client, clientErr := cloud.EDSClient(region.ID, credentials.AccessKey, credentials.SecretKey, credentials.SessionToken)
			if clientErr == nil {
				var count int
				count, clientErr = cloud.EDSDesktopCount(ctx, client.Desktop, region.ID)
				if clientErr == nil {
					counts[i].Desktops, counts[i].Available = count, true
				}
			}
			if clientErr != nil {
				slog.Warn("Alibaba EDS region count failed", "account_id", accountID, "region", region.ID, "error", clientErr)
			}
		}()
	}
	wg.Wait()
	total := 0
	for _, item := range counts {
		if item.Available && item.Desktops > 0 {
			total += item.Desktops
		}
	}
	sort.Slice(counts, func(i, j int) bool { return counts[i].ID < counts[j].ID })
	payload := edsRegionResponse{Data: counts, TotalDesktops: total}
	if err = a.saveServiceSnapshot(ctx, workspaceID, accountID, "eds.regions", "", payload); err != nil {
		return nil, err
	}
	return counts, nil
}

func (a *App) collectEDSDesktops(ctx context.Context, workspaceID, accountID int64, target string, regions []edsRegionCount) error {
	credentials, _, err := a.edsCredentials(ctx, workspaceID, accountID)
	if err != nil {
		return err
	}
	if target != "all" {
		client, clientErr := cloud.EDSClient(target, credentials.AccessKey, credentials.SecretKey, credentials.SessionToken)
		if clientErr != nil {
			return clientErr
		}
		items, listErr := cloud.EDSDesktops(ctx, client.Desktop, target)
		if listErr != nil {
			return listErr
		}
		return a.saveServiceSnapshot(ctx, workspaceID, accountID, "eds.desktops", target, map[string]any{"data": items, "failed_regions": []string{}})
	}
	regionItems := make([][]*cloud.EDSDesktop, len(regions))
	failed := []string{}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i, region := range regions {
		i, region := i, region
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case a.regionSlots <- struct{}{}:
			case <-ctx.Done():
				mu.Lock()
				failed = append(failed, region.ID)
				mu.Unlock()
				return
			}
			defer func() { <-a.regionSlots }()
			client, clientErr := cloud.EDSClient(region.ID, credentials.AccessKey, credentials.SecretKey, credentials.SessionToken)
			if clientErr == nil {
				regionItems[i], clientErr = cloud.EDSDesktops(ctx, client.Desktop, region.ID)
			}
			if clientErr != nil {
				mu.Lock()
				failed = append(failed, region.ID)
				mu.Unlock()
				slog.Warn("Alibaba EDS desktop list failed", "account_id", accountID, "region", region.ID, "error", clientErr)
			}
		}()
	}
	wg.Wait()
	items := []*cloud.EDSDesktop{}
	for _, batch := range regionItems {
		items = append(items, batch...)
	}
	sort.Strings(failed)
	if len(regions) > 0 && len(failed) == len(regions) {
		return errors.New("Alibaba EDS could not list desktops in any region")
	}
	return a.saveServiceSnapshot(ctx, workspaceID, accountID, "eds.desktops", "all", map[string]any{"data": items, "failed_regions": failed})
}

func (a *App) collectEDSUsers(ctx context.Context, workspaceID, accountID int64, region string) error {
	credentials, _, err := a.edsCredentials(ctx, workspaceID, accountID)
	if err != nil {
		return err
	}
	client, err := cloud.EDSClient(region, credentials.AccessKey, credentials.SecretKey, credentials.SessionToken)
	if err != nil {
		return err
	}
	items, err := cloud.EDSUsers(ctx, client.User)
	if err != nil {
		return err
	}
	return a.saveServiceSnapshot(ctx, workspaceID, accountID, "eds.users", region, map[string]any{"data": items})
}
