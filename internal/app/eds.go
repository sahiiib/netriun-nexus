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

var cloudResourcePattern = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$")
var edsUsernamePattern = regexp.MustCompile("^[a-z0-9_]{3,24}$")
var edsHostnamePattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?$`)

func edsRegionsCacheKey(workspaceID, accountID int64) string {
	return fmt.Sprintf("eds:regions:v2:%d:%d", workspaceID, accountID)
}

func (a *App) edsAccount(w http.ResponseWriter, r *http.Request, mode string) (int64, string, *cloud.EDSClients, bool) {
	accountID, ok := pathID(w, r, "id")
	if !ok {
		return 0, "", nil, false
	}
	if !a.accountAccess(r, accountID, mode) {
		problem(w, 403, "Cloud account access required")
		return 0, "", nil, false
	}
	region := strings.TrimSpace(r.URL.Query().Get("region"))
	if region == "" || !regionPattern.MatchString(region) {
		problem(w, 400, "A valid Alibaba Cloud region is required")
		return 0, "", nil, false
	}
	c, err := a.credentials(r.Context(), current(r).WorkspaceID, accountID, "alibaba")
	if err != nil {
		problem(w, 400, "The selected account is not an Alibaba Cloud connection")
		return 0, "", nil, false
	}
	clients, err := cloud.EDSClient(region, c.AccessKey, c.SecretKey, c.SessionToken)
	if err != nil {
		problem(w, 502, "Could not initialize Alibaba EDS")
		return 0, "", nil, false
	}
	return accountID, region, clients, true
}

func edsContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 35*time.Second)
}

func edsProviderError(w http.ResponseWriter, operation string, accountID int64, region string, err error) {
	slog.Warn("Alibaba EDS request failed", "operation", operation, "account_id", accountID, "region", region, "error", err)
	problem(w, 502, "Alibaba EDS rejected the request; check the region, RAM permissions, resource state, and request values")
}

func (a *App) edsDesktops(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(r.URL.Query().Get("region")) == "all" {
		a.edsDesktopsAllRegions(w, r)
		return
	}
	accountID, region, clients, ok := a.edsAccount(w, r, "view")
	if !ok {
		return
	}
	ctx, cancel := edsContext(r)
	defer cancel()
	items, err := cloud.EDSDesktops(ctx, clients.Desktop, region)
	if err != nil {
		edsProviderError(w, "describe_desktops", accountID, region, err)
		return
	}
	write(w, 200, map[string]any{"data": items})
}

func (a *App) edsDesktopsAllRegions(w http.ResponseWriter, r *http.Request) {
	accountID, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if !a.accountAccess(r, accountID, "view") {
		problem(w, 403, "Cloud account access required")
		return
	}
	u := current(r)
	credentials, err := a.credentials(r.Context(), u.WorkspaceID, accountID, "alibaba")
	if err != nil {
		problem(w, 400, "The selected account is not an Alibaba Cloud connection")
		return
	}
	seedRegion := "cn-hangzhou"
	if err = a.DB.QueryRow(r.Context(), `SELECT COALESCE((SELECT min(region) FROM instances WHERE account_id=$1), NULLIF(regions[1],''), 'cn-hangzhou') FROM cloud_accounts WHERE id=$1 AND workspace_id=$2`, accountID, u.WorkspaceID).Scan(&seedRegion); err != nil {
		dbError(w, err)
		return
	}
	seed, err := cloud.EDSClient(seedRegion, credentials.AccessKey, credentials.SecretKey, credentials.SessionToken)
	if err != nil {
		edsProviderError(w, "describe_desktops_all", accountID, seedRegion, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 75*time.Second)
	defer cancel()
	regions, err := cloud.EDSRegions(ctx, seed.Desktop)
	if err != nil {
		edsProviderError(w, "describe_desktops_all", accountID, seedRegion, err)
		return
	}
	regionItems := make([][]*cloud.EDSDesktop, len(regions))
	failed := []string{}
	succeeded := 0
	var wg sync.WaitGroup
	var mu sync.Mutex
	limit := make(chan struct{}, 6)
	for i, region := range regions {
		i, region := i, region
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case limit <- struct{}{}:
			case <-ctx.Done():
				mu.Lock()
				failed = append(failed, region.ID)
				mu.Unlock()
				return
			}
			defer func() { <-limit }()
			client, clientErr := cloud.EDSClient(region.ID, credentials.AccessKey, credentials.SecretKey, credentials.SessionToken)
			if clientErr == nil {
				regionItems[i], clientErr = cloud.EDSDesktops(ctx, client.Desktop, region.ID)
			}
			mu.Lock()
			defer mu.Unlock()
			if clientErr != nil {
				failed = append(failed, region.ID)
				slog.Warn("Alibaba EDS region list failed", "account_id", accountID, "region", region.ID, "error", clientErr)
				return
			}
			succeeded++
		}()
	}
	wg.Wait()
	if succeeded == 0 && len(regions) > 0 {
		problem(w, 502, "Alibaba EDS could not list desktops in any region")
		return
	}
	items := []*cloud.EDSDesktop{}
	for _, regionResult := range regionItems {
		items = append(items, regionResult...)
	}
	sort.Strings(failed)
	write(w, 200, map[string]any{"data": items, "failed_regions": failed})
}

func (a *App) edsRegions(w http.ResponseWriter, r *http.Request) {
	accountID, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if !a.accountAccess(r, accountID, "view") {
		problem(w, 403, "Cloud account access required")
		return
	}
	u := current(r)
	type regionCount struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Desktops  int    `json:"desktops"`
		Available bool   `json:"available"`
	}
	type regionResponse struct {
		Data          []regionCount `json:"data"`
		TotalDesktops int           `json:"total_desktops"`
	}
	cacheKey := edsRegionsCacheKey(u.WorkspaceID, accountID)
	if raw, cacheErr := a.Redis.Get(r.Context(), cacheKey).Bytes(); cacheErr == nil {
		var cached regionResponse
		if json.Unmarshal(raw, &cached) == nil {
			write(w, 200, cached)
			return
		}
	}
	credentials, err := a.credentials(r.Context(), u.WorkspaceID, accountID, "alibaba")
	if err != nil {
		problem(w, 400, "The selected account is not an Alibaba Cloud connection")
		return
	}
	var seedRegion string
	err = a.DB.QueryRow(r.Context(), `SELECT COALESCE((SELECT min(region) FROM instances WHERE account_id=$1), NULLIF(regions[1],''), 'cn-hangzhou') FROM cloud_accounts WHERE id=$1 AND workspace_id=$2`, accountID, u.WorkspaceID).Scan(&seedRegion)
	if err != nil {
		dbError(w, err)
		return
	}
	seed, err := cloud.EDSClient(seedRegion, credentials.AccessKey, credentials.SecretKey, credentials.SessionToken)
	if err != nil {
		edsProviderError(w, "describe_regions", accountID, seedRegion, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 55*time.Second)
	defer cancel()
	regions, err := cloud.EDSRegions(ctx, seed.Desktop)
	if err != nil {
		edsProviderError(w, "describe_regions", accountID, seedRegion, err)
		return
	}
	counts := make([]regionCount, len(regions))
	var wg sync.WaitGroup
	limit := make(chan struct{}, 6)
	for i, region := range regions {
		counts[i] = regionCount{ID: region.ID, Name: region.Name, Desktops: -1}
		i, region := i, region
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case limit <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-limit }()
			item := counts[i]
			client, clientErr := cloud.EDSClient(region.ID, credentials.AccessKey, credentials.SecretKey, credentials.SessionToken)
			if clientErr == nil {
				count, listErr := cloud.EDSDesktopCount(ctx, client.Desktop, region.ID)
				if listErr == nil {
					item.Desktops, item.Available = count, true
				} else {
					slog.Warn("Alibaba EDS region count failed", "account_id", accountID, "region", region.ID, "error", listErr)
				}
			}
			counts[i] = item
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
	payload := regionResponse{Data: counts, TotalDesktops: total}
	if raw, marshalErr := json.Marshal(payload); marshalErr == nil {
		if cacheErr := a.Redis.Set(r.Context(), cacheKey, raw, 5*time.Minute).Err(); cacheErr != nil {
			slog.Warn("Alibaba EDS region cache write failed", "account_id", accountID, "error", cacheErr)
		}
	}
	write(w, 200, payload)
}

func (a *App) edsCatalog(w http.ResponseWriter, r *http.Request) {
	accountID, region, clients, ok := a.edsAccount(w, r, "view")
	if !ok {
		return
	}
	ctx, cancel := edsContext(r)
	defer cancel()
	result, err := cloud.EDSCatalogForRegion(ctx, clients.Desktop, region)
	if err != nil {
		edsProviderError(w, "describe_catalog", accountID, region, err)
		return
	}
	custom, customErr := cloud.EDSCustomCatalogForRegion(ctx, clients.Desktop, region)
	if customErr != nil {
		slog.Warn("Alibaba EDS custom catalog unavailable", "account_id", accountID, "region", region, "error", customErr)
	} else {
		result.DesktopTypes, result.Images = custom.DesktopTypes, custom.Images
	}
	write(w, 200, result)
}

func (a *App) edsUsers(w http.ResponseWriter, r *http.Request) {
	accountID, region, clients, ok := a.edsAccount(w, r, "view")
	if !ok {
		return
	}
	ctx, cancel := edsContext(r)
	defer cancel()
	items, err := cloud.EDSUsers(ctx, clients.User)
	if err != nil {
		edsProviderError(w, "describe_users", accountID, region, err)
		return
	}
	write(w, 200, map[string]any{"data": items})
}

func (a *App) createEDSDesktop(w http.ResponseWriter, r *http.Request) {
	accountID, region, clients, ok := a.edsAccount(w, r, "manage")
	if !ok {
		return
	}
	var in struct {
		OfficeSiteID    string   `json:"office_site_id"`
		BundleID        string   `json:"bundle_id"`
		DesktopType     string   `json:"desktop_type"`
		ImageID         string   `json:"image_id"`
		DefaultLanguage string   `json:"default_language"`
		SystemDiskSize  int32    `json:"system_disk_size"`
		DataDiskSize    int32    `json:"data_disk_size"`
		PolicyGroupID   string   `json:"policy_group_id"`
		Hostname        string   `json:"hostname"`
		Name            string   `json:"name"`
		Amount          int32    `json:"amount"`
		Period          int32    `json:"period"`
		ChargeType      string   `json:"charge_type"`
		PeriodUnit      string   `json:"period_unit"`
		EndUserIDs      []string `json:"end_user_ids"`
		AutoPay         bool     `json:"auto_pay"`
		AutoRenew       bool     `json:"auto_renew"`
		ConfirmCost     bool     `json:"confirm_cost"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name, in.Hostname = strings.TrimSpace(in.Name), strings.TrimSpace(in.Hostname)
	if !in.ConfirmCost {
		problem(w, 400, "Explicit cost confirmation is required")
		return
	}
	if !cloudResourcePattern.MatchString(in.OfficeSiteID) || len(in.Name) < 1 || len(in.Name) > 64 || in.Amount < 1 || in.Amount > 10 {
		problem(w, 400, "Provide a valid office site, name, and an amount from 1 to 10")
		return
	}
	if in.PolicyGroupID != "" && !cloudResourcePattern.MatchString(in.PolicyGroupID) {
		problem(w, 400, "Invalid optional security policy")
		return
	}
	if in.Hostname != "" && (!edsHostnamePattern.MatchString(in.Hostname) || strings.Contains(in.Hostname, "--") || strings.Trim(in.Hostname, "0123456789") == "" || in.Amount != 1) {
		problem(w, 400, "Hostname must be 2–15 letters, digits, or hyphens, cannot be only digits, and is supported here for one desktop at a time")
		return
	}
	if in.BundleID != "" {
		if !cloudResourcePattern.MatchString(in.BundleID) {
			problem(w, 400, "Invalid desktop bundle")
			return
		}
	} else if !cloudResourcePattern.MatchString(in.DesktopType) || !cloudResourcePattern.MatchString(in.ImageID) || in.SystemDiskSize < 60 || in.SystemDiskSize > 500 || in.SystemDiskSize%10 != 0 || in.DataDiskSize != 0 && (in.DataDiskSize < 40 || in.DataDiskSize > 2040 || in.DataDiskSize%10 != 0) {
		problem(w, 400, "Custom desktops require a valid CPU/RAM specification, image, 60–500 GiB system disk, and optional 40–2040 GiB data disk in 10 GiB steps")
		return
	}
	if in.DefaultLanguage != "" && in.DefaultLanguage != "en-US" && in.DefaultLanguage != "zh-CN" && in.DefaultLanguage != "zh-HK" && in.DefaultLanguage != "ja-JP" {
		problem(w, 400, "Invalid desktop language")
		return
	}
	if in.ChargeType != "PostPaid" && in.ChargeType != "PrePaid" {
		problem(w, 400, "Charge type must be PostPaid or PrePaid")
		return
	}
	if in.ChargeType == "PrePaid" && (in.Period < 1 || in.Period > 60 || (in.PeriodUnit != "Month" && in.PeriodUnit != "Year")) {
		problem(w, 400, "A valid subscription period is required")
		return
	}
	for _, id := range in.EndUserIDs {
		if !edsUsernamePattern.MatchString(id) {
			problem(w, 400, "Invalid EDS user ID")
			return
		}
	}
	u := current(r)
	if err := a.record(r.Context(), u.WorkspaceID, u.ID, u.Username, "eds.desktop.create.requested", in.Name, map[string]any{"account_id": accountID, "region": region, "amount": in.Amount, "charge_type": in.ChargeType, "auto_pay": in.AutoPay}); err != nil {
		problem(w, 503, "Desktop was not submitted because audit storage is unavailable")
		return
	}
	ctx, cancel := edsContext(r)
	defer cancel()
	result, err := cloud.EDSCreateDesktop(ctx, clients.Desktop, cloud.CreateDesktopInput{Region: region, OfficeSiteID: in.OfficeSiteID, BundleID: in.BundleID, DesktopType: in.DesktopType, ImageID: in.ImageID, DefaultLanguage: in.DefaultLanguage, SystemDiskSize: in.SystemDiskSize, DataDiskSize: in.DataDiskSize, PolicyGroupID: in.PolicyGroupID, Hostname: in.Hostname, Name: in.Name, Amount: in.Amount, Period: in.Period, ChargeType: in.ChargeType, PeriodUnit: in.PeriodUnit, EndUserIDs: in.EndUserIDs, AutoPay: in.AutoPay, AutoRenew: in.AutoRenew})
	if err != nil {
		a.audit(r, "eds.desktop.create.failed", in.Name, nil)
		edsProviderError(w, "create_desktops", accountID, region, err)
		return
	}
	a.audit(r, "eds.desktop.create.accepted", in.Name, nil)
	if cacheErr := a.Redis.Del(r.Context(), edsRegionsCacheKey(u.WorkspaceID, accountID)).Err(); cacheErr != nil {
		slog.Warn("Alibaba EDS region cache invalidation failed", "account_id", accountID, "error", cacheErr)
	}
	write(w, 202, result)
}

func (a *App) edsDesktopAction(w http.ResponseWriter, r *http.Request) {
	accountID, region, clients, ok := a.edsAccount(w, r, "operate")
	if !ok {
		return
	}
	desktopID := r.PathValue("desktopID")
	if !cloudResourcePattern.MatchString(desktopID) {
		problem(w, 400, "Invalid desktop ID")
		return
	}
	var in struct {
		Action string `json:"action"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Action != "start" && in.Action != "stop" && in.Action != "reboot" {
		problem(w, 400, "Action must be start, stop or reboot")
		return
	}
	u := current(r)
	if err := a.record(r.Context(), u.WorkspaceID, u.ID, u.Username, "eds.desktop."+in.Action+".requested", desktopID, map[string]string{"region": region}); err != nil {
		problem(w, 503, "Action was not submitted because audit storage is unavailable")
		return
	}
	ctx, cancel := edsContext(r)
	defer cancel()
	if err := cloud.EDSDesktopAction(ctx, clients.Desktop, region, desktopID, in.Action); err != nil {
		a.audit(r, "eds.desktop."+in.Action+".failed", desktopID, nil)
		edsProviderError(w, "desktop_"+in.Action, accountID, region, err)
		return
	}
	a.audit(r, "eds.desktop."+in.Action+".accepted", desktopID, nil)
	write(w, 202, map[string]string{"status": "accepted", "action": in.Action, "desktop_id": desktopID})
}

func (a *App) renewEDSDesktop(w http.ResponseWriter, r *http.Request) {
	accountID, region, clients, ok := a.edsAccount(w, r, "manage")
	if !ok {
		return
	}
	desktopID := r.PathValue("desktopID")
	if !cloudResourcePattern.MatchString(desktopID) {
		problem(w, 400, "Invalid desktop ID")
		return
	}
	var in struct {
		Period      int32  `json:"period"`
		PeriodUnit  string `json:"period_unit"`
		AutoPay     bool   `json:"auto_pay"`
		ConfirmCost bool   `json:"confirm_cost"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !in.ConfirmCost {
		problem(w, 400, "Explicit cost confirmation is required")
		return
	}
	if in.Period < 1 || in.Period > 60 || (in.PeriodUnit != "Month" && in.PeriodUnit != "Year") {
		problem(w, 400, "Provide a valid renewal period")
		return
	}
	u := current(r)
	if err := a.record(r.Context(), u.WorkspaceID, u.ID, u.Username, "eds.desktop.renew.requested", desktopID, map[string]any{"region": region, "period": in.Period, "period_unit": in.PeriodUnit, "auto_pay": in.AutoPay}); err != nil {
		problem(w, 503, "Renewal was not submitted because audit storage is unavailable")
		return
	}
	ctx, cancel := edsContext(r)
	defer cancel()
	result, err := cloud.EDSRenew(ctx, clients.Desktop, region, desktopID, in.PeriodUnit, in.Period, in.AutoPay)
	if err != nil {
		a.audit(r, "eds.desktop.renew.failed", desktopID, nil)
		edsProviderError(w, "renew_desktop", accountID, region, err)
		return
	}
	a.audit(r, "eds.desktop.renew.accepted", desktopID, nil)
	write(w, 202, result)
}

func (a *App) changeEDSEntitlement(w http.ResponseWriter, r *http.Request) {
	accountID, region, clients, ok := a.edsAccount(w, r, "operate")
	if !ok {
		return
	}
	desktopID := r.PathValue("desktopID")
	if !cloudResourcePattern.MatchString(desktopID) {
		problem(w, 400, "Invalid desktop ID")
		return
	}
	var in struct {
		Operation  string   `json:"operation"`
		EndUserIDs []string `json:"end_user_ids"`
	}
	if !decode(w, r, &in) {
		return
	}
	if (in.Operation != "bind" && in.Operation != "revoke") || len(in.EndUserIDs) < 1 || len(in.EndUserIDs) > 100 {
		problem(w, 400, "Choose bind or revoke and at least one EDS user")
		return
	}
	for _, id := range in.EndUserIDs {
		if !edsUsernamePattern.MatchString(id) {
			problem(w, 400, "Invalid EDS user ID")
			return
		}
	}
	u := current(r)
	if err := a.record(r.Context(), u.WorkspaceID, u.ID, u.Username, "eds.desktop.users."+in.Operation+".requested", desktopID, map[string]any{"region": region, "end_user_ids": in.EndUserIDs}); err != nil {
		problem(w, 503, "Assignment was not submitted because audit storage is unavailable")
		return
	}
	ctx, cancel := edsContext(r)
	defer cancel()
	if err := cloud.EDSEntitlement(ctx, clients.Desktop, region, desktopID, in.EndUserIDs, in.Operation == "bind"); err != nil {
		a.audit(r, "eds.desktop.users."+in.Operation+".failed", desktopID, nil)
		edsProviderError(w, "modify_user_entitlement", accountID, region, err)
		return
	}
	a.audit(r, "eds.desktop.users."+in.Operation+".accepted", desktopID, nil)
	write(w, 202, map[string]string{"status": "accepted", "operation": in.Operation})
}

func (a *App) createEDSUser(w http.ResponseWriter, r *http.Request) {
	accountID, region, clients, ok := a.edsAccount(w, r, "manage")
	if !ok {
		return
	}
	var in struct {
		Username     string `json:"username"`
		Email        string `json:"email"`
		DisplayName  string `json:"display_name"`
		Password     string `json:"password"`
		IsLocalAdmin bool   `json:"is_local_admin"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Username, in.Email, in.DisplayName = strings.TrimSpace(in.Username), strings.TrimSpace(in.Email), strings.TrimSpace(in.DisplayName)
	if !edsUsernamePattern.MatchString(in.Username) || len(in.Email) < 3 || len(in.Email) > 254 || !strings.Contains(in.Email, "@") || len(in.DisplayName) > 64 || (in.Password != "" && (len(in.Password) < 8 || len(in.Password) > 30)) {
		problem(w, 400, "Provide a valid lowercase user ID, email, display name, and optional 8–30 character password")
		return
	}
	u := current(r)
	if err := a.record(r.Context(), u.WorkspaceID, u.ID, u.Username, "eds.user.create.requested", in.Username, map[string]any{"email": in.Email, "local_admin": in.IsLocalAdmin}); err != nil {
		problem(w, 503, "User was not submitted because audit storage is unavailable")
		return
	}
	ctx, cancel := edsContext(r)
	defer cancel()
	result, err := cloud.EDSCreateUser(ctx, clients.User, in.Username, in.Email, in.DisplayName, in.Password, in.IsLocalAdmin)
	if err != nil {
		a.audit(r, "eds.user.create.failed", in.Username, nil)
		edsProviderError(w, "create_user", accountID, region, err)
		return
	}
	if result.AllSucceed != nil && !*result.AllSucceed {
		a.audit(r, "eds.user.create.failed", in.Username, nil)
		problem(w, 502, "Alibaba EDS did not create the user")
		return
	}
	a.audit(r, "eds.user.create.accepted", in.Username, nil)
	write(w, 202, result)
}

func (a *App) changeEDSPolicy(w http.ResponseWriter, r *http.Request) {
	accountID, region, clients, ok := a.edsAccount(w, r, "manage")
	if !ok {
		return
	}
	desktopID := r.PathValue("desktopID")
	var in struct {
		PolicyGroupID string `json:"policy_group_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !cloudResourcePattern.MatchString(desktopID) || !cloudResourcePattern.MatchString(in.PolicyGroupID) {
		problem(w, 400, "Invalid desktop or policy ID")
		return
	}
	u := current(r)
	if err := a.record(r.Context(), u.WorkspaceID, u.ID, u.Username, "eds.desktop.policy.requested", desktopID, map[string]string{"region": region, "policy_group_id": in.PolicyGroupID}); err != nil {
		problem(w, 503, "Policy change was not submitted because audit storage is unavailable")
		return
	}
	ctx, cancel := edsContext(r)
	defer cancel()
	result, err := cloud.EDSChangePolicy(ctx, clients.Desktop, region, desktopID, in.PolicyGroupID)
	if err != nil {
		a.audit(r, "eds.desktop.policy.failed", desktopID, nil)
		edsProviderError(w, "change_policy", accountID, region, err)
		return
	}
	a.audit(r, "eds.desktop.policy.accepted", desktopID, nil)
	write(w, 202, result)
}

func (a *App) setEDSMaintenance(w http.ResponseWriter, r *http.Request) {
	accountID, region, clients, ok := a.edsAccount(w, r, "operate")
	if !ok {
		return
	}
	desktopID := r.PathValue("desktopID")
	var in struct {
		Mode string `json:"mode"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Mode = strings.ToUpper(in.Mode)
	if !cloudResourcePattern.MatchString(desktopID) || (in.Mode != "ENTER" && in.Mode != "EXIT") {
		problem(w, 400, "Mode must be ENTER or EXIT")
		return
	}
	u := current(r)
	if err := a.record(r.Context(), u.WorkspaceID, u.ID, u.Username, "eds.desktop.maintenance."+strings.ToLower(in.Mode)+".requested", desktopID, map[string]string{"region": region}); err != nil {
		problem(w, 503, "Maintenance change was not submitted because audit storage is unavailable")
		return
	}
	ctx, cancel := edsContext(r)
	defer cancel()
	if err := cloud.EDSMaintenance(ctx, clients.Desktop, region, desktopID, in.Mode); err != nil {
		a.audit(r, "eds.desktop.maintenance.failed", desktopID, nil)
		edsProviderError(w, "set_maintenance", accountID, region, err)
		return
	}
	a.audit(r, "eds.desktop.maintenance.accepted", desktopID, map[string]string{"mode": in.Mode})
	write(w, 202, map[string]string{"status": "accepted", "mode": in.Mode})
}

func (a *App) runEDSCommand(w http.ResponseWriter, r *http.Request) {
	accountID, region, clients, ok := a.edsAccount(w, r, "operate")
	if !ok {
		return
	}
	desktopID := r.PathValue("desktopID")
	var in struct {
		Command     string `json:"command"`
		CommandType string `json:"command_type"`
		Timeout     int64  `json:"timeout"`
		Confirm     bool   `json:"confirm"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !cloudResourcePattern.MatchString(desktopID) || len(in.Command) < 1 || len(in.Command) > 16*1024 || (in.CommandType != "RunPowerShellScript" && in.CommandType != "RunBatScript") || in.Timeout < 10 || in.Timeout > 86400 || !in.Confirm {
		problem(w, 400, "Provide a confirmed PowerShell or Bat command up to 16 KB and a timeout from 10 to 86400 seconds")
		return
	}
	u := current(r)
	details := map[string]any{"region": region, "command_type": in.CommandType, "timeout": in.Timeout, "command_digest": secure.Digest(in.Command)}
	if err := a.record(r.Context(), u.WorkspaceID, u.ID, u.Username, "eds.desktop.command.requested", desktopID, details); err != nil {
		problem(w, 503, "Command was not submitted because audit storage is unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(in.Timeout+20)*time.Second)
	defer cancel()
	status, err := cloud.EDSDesktopStatus(ctx, clients.Desktop, region, desktopID)
	if err != nil {
		edsProviderError(w, "command_desktop_status", accountID, region, err)
		return
	}
	if !strings.EqualFold(status, "Running") {
		problem(w, 409, "Remote commands require a running EDS desktop")
		return
	}
	result, err := cloud.EDSRunCommand(ctx, clients.Desktop, region, desktopID, in.Command, in.CommandType, in.Timeout)
	if err != nil {
		a.audit(r, "eds.desktop.command.failed", desktopID, details)
		edsProviderError(w, "run_command", accountID, region, err)
		return
	}
	a.audit(r, "eds.desktop.command.accepted", desktopID, details)
	write(w, 202, result)
}

func (a *App) edsCommandResult(w http.ResponseWriter, r *http.Request) {
	accountID, region, clients, ok := a.edsAccount(w, r, "operate")
	if !ok {
		return
	}
	desktopID, invokeID := r.PathValue("desktopID"), r.PathValue("invokeID")
	if !cloudResourcePattern.MatchString(desktopID) || !cloudResourcePattern.MatchString(invokeID) {
		problem(w, 400, "Invalid desktop or command invocation ID")
		return
	}
	ctx, cancel := edsContext(r)
	defer cancel()
	result, err := cloud.EDSInvocation(ctx, clients.Desktop, region, desktopID, invokeID)
	if err != nil {
		edsProviderError(w, "describe_invocation", accountID, region, err)
		return
	}
	write(w, 200, result)
}

func (a *App) changeEDSBilling(w http.ResponseWriter, r *http.Request) {
	accountID, region, clients, ok := a.edsAccount(w, r, "manage")
	if !ok {
		return
	}
	desktopID := r.PathValue("desktopID")
	var in struct {
		ChargeType  string `json:"charge_type"`
		Period      int32  `json:"period"`
		PeriodUnit  string `json:"period_unit"`
		AutoPay     bool   `json:"auto_pay"`
		ConfirmCost bool   `json:"confirm_cost"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !cloudResourcePattern.MatchString(desktopID) || (in.ChargeType != "PrePaid" && in.ChargeType != "PostPaid") || !in.ConfirmCost {
		problem(w, 400, "Provide a billing method and explicit cost confirmation")
		return
	}
	validPeriod := in.PeriodUnit == "Week" && in.Period == 1 || in.PeriodUnit == "Month" && (in.Period == 1 || in.Period == 2 || in.Period == 3 || in.Period == 6) || in.PeriodUnit == "Year" && in.Period >= 1 && in.Period <= 5
	if in.ChargeType == "PrePaid" && !validPeriod {
		problem(w, 400, "PrePaid periods are Week: 1; Month: 1, 2, 3, 6; or Year: 1–5")
		return
	}
	u := current(r)
	details := map[string]any{"region": region, "charge_type": in.ChargeType, "period": in.Period, "period_unit": in.PeriodUnit, "auto_pay": in.AutoPay}
	if err := a.record(r.Context(), u.WorkspaceID, u.ID, u.Username, "eds.desktop.billing.requested", desktopID, details); err != nil {
		problem(w, 503, "Billing change was not submitted because audit storage is unavailable")
		return
	}
	ctx, cancel := edsContext(r)
	defer cancel()
	result, err := cloud.EDSChangeBilling(ctx, clients.Desktop, region, desktopID, in.ChargeType, in.PeriodUnit, in.Period, in.AutoPay)
	if err != nil {
		a.audit(r, "eds.desktop.billing.failed", desktopID, details)
		edsProviderError(w, "change_billing", accountID, region, err)
		return
	}
	a.audit(r, "eds.desktop.billing.accepted", desktopID, details)
	write(w, 202, result)
}
