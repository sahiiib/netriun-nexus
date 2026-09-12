package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

type fakeMailer struct {
	lastURL string
}

func (m *fakeMailer) SendVerification(_, _, verifyURL string) error {
	m.lastURL = verifyURL
	return nil
}

// Only enable against an isolated test database. This test truncates application tables.
func TestIntegration(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	redisURL := os.Getenv("TEST_REDIS_URL")
	if dsn == "" || redisURL == "" {
		t.Skip("set TEST_DATABASE_URL and TEST_REDIS_URL for integration tests")
	}
	if !strings.Contains(dsn, "ccmp_test") {
		t.Fatal("test database must be named ccmp_test")
	}
	t.Setenv("DATABASE_URL", dsn)
	t.Setenv("REDIS_URL", redisURL)
	t.Setenv("ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("ADMIN_USERNAME", "testadmin")
	t.Setenv("ADMIN_EMAIL", "testadmin@example.com")
	t.Setenv("ADMIN_PASSWORD", "Test-admin-password1!")
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_PORT", "587")
	t.Setenv("SMTP_USERNAME", "sender@example.com")
	t.Setenv("SMTP_PASSWORD", "smtp-password")
	t.Setenv("SMTP_FROM_ADDRESS", "sender@example.com")
	t.Setenv("SMTP_FROM_NAME", "Netriun Nexus")
	t.Setenv("COOKIE_SECURE", "false")
	t.Setenv("APP_ORIGIN", "http://localhost:8080")
	ctx := context.Background()
	a, err := New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mailer := &fakeMailer{}
	a.Mailer = mailer
	defer a.Close()
	if _, err = a.DB.Exec(ctx, "TRUNCATE workspaces RESTART IDENTITY CASCADE"); err != nil {
		t.Fatal(err)
	}
	if err = a.Redis.FlushDB(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	if err = a.bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	var workspaceID int64
	if err = a.DB.QueryRow(ctx, "SELECT workspace_id FROM users WHERE username='testadmin'").Scan(&workspaceID); err != nil {
		t.Fatal(err)
	}
	h := a.Handler()
	request := func(method, path, token string, body any, status int) *httptest.ResponseRecorder {
		t.Helper()
		var b bytes.Buffer
		if body != nil {
			json.NewEncoder(&b).Encode(body)
		}
		r := httptest.NewRequest(method, path, &b)
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Header().Get("X-Request-ID") == "" {
			t.Fatal("missing response request ID")
		}
		if w.Code != status {
			t.Fatalf("%s %s: expected %d got %d: %s", method, path, status, w.Code, w.Body.String())
		}
		return w
	}
	login := func(email, password string) string {
		t.Helper()
		w := request("POST", "/api/v1/auth/login", "", map[string]string{"email": email, "password": password}, 200)
		var out struct {
			Token string `json:"token"`
		}
		json.Unmarshal(w.Body.Bytes(), &out)
		if out.Token == "" {
			t.Fatal("missing token")
		}
		cookies := w.Result().Cookies()
		if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
			t.Fatal("unsafe session cookie")
		}
		return out.Token
	}
	verifyLatest := func() {
		t.Helper()
		parsed, parseErr := url.Parse(mailer.lastURL)
		if parseErr != nil || parsed.Query().Get("token") == "" {
			t.Fatalf("missing verification URL: %q err=%v", mailer.lastURL, parseErr)
		}
		request("GET", "/verify-email?token="+url.QueryEscape(parsed.Query().Get("token")), "", nil, http.StatusSeeOther)
	}
	idFrom := func(w *httptest.ResponseRecorder) int64 {
		t.Helper()
		var v struct {
			ID int64 `json:"id"`
		}
		if err = json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v.ID
	}
	request("GET", "/api/v1/instances", "", nil, 401)
	request("POST", "/api/v1/accounts/test", "", map[string]string{"provider": "aws"}, 401)
	request("POST", "/api/v1/auth/login", "", map[string]string{"email": "testadmin@example.com", "password": "wrong"}, 401)
	adminToken := login("testadmin@example.com", "Test-admin-password1!")
	proveConnection := func(email, provider string, credentials Credentials) {
		t.Helper()
		var u User
		if err = a.DB.QueryRow(ctx, "SELECT id,workspace_id FROM users WHERE email=$1", email).Scan(&u.ID, &u.WorkspaceID); err != nil {
			t.Fatal(err)
		}
		if message := validateCredentials(provider, &credentials); message != "" {
			t.Fatal(message)
		}
		if err = a.Redis.Set(ctx, connectionProofKey(u, provider, 0, credentials), "1", time.Minute).Err(); err != nil {
			t.Fatal(err)
		}
	}
	request("POST", "/api/v1/accounts/test", adminToken, map[string]any{"provider": "azure", "credentials": map[string]string{"tenant_id": "invalid"}}, 400)
	request("POST", "/api/v1/accounts", adminToken, map[string]any{"name": "Untested", "provider": "aws", "credentials": map[string]string{"access_key_id": "untested-key", "secret_access_key": "untested-secret"}}, http.StatusConflict)
	group1 := idFrom(request("POST", "/api/v1/groups", adminToken, map[string]any{"name": "Team A", "view_dashboard": true, "manage_cloud_accounts": true, "manage_group_members": true}, 200))
	group2 := idFrom(request("POST", "/api/v1/groups", adminToken, map[string]any{"name": "Team B", "view_dashboard": true}, 200))
	uid := idFrom(request("POST", "/api/v1/users", adminToken, map[string]string{"username": "viewer", "email": "viewer@example.com", "password": "Viewer-password1!", "role": "user"}, 200))
	verifyLatest()
	request("PUT", fmt.Sprintf("/api/v1/groups/%d/members/%d", group1, uid), adminToken, map[string]string{"role": "viewer"}, 200)
	acct := func(name string, gid int64) int64 {
		proveConnection("testadmin@example.com", "aws", Credentials{AccessKey: "test-key", SecretKey: "secret-must-not-leak"})
		return idFrom(request("POST", "/api/v1/accounts", adminToken, map[string]any{"name": name, "owner": "Platform", "group_id": gid, "regions": []string{"us-east-1"}, "credentials": map[string]string{"access_key_id": "test-key", "secret_access_key": "secret-must-not-leak"}}, 200))
	}
	account1, account2 := acct("Account A", group1), acct("Account B", group2)
	proveConnection("testadmin@example.com", "alibaba", Credentials{AccessKey: "LTAI-test", SecretKey: "alibaba-secret"})
	alibabaAccount := idFrom(request("POST", "/api/v1/accounts", adminToken, map[string]any{"name": "Alibaba Production", "provider": "alibaba", "owner": "Platform", "group_id": group2, "regions": []string{"cn-hangzhou", "ap-southeast-1"}, "credentials": map[string]string{"access_key_id": "LTAI-test", "secret_access_key": "alibaba-secret"}}, 200))
	var alibabaProvider, alibabaCipher string
	if err = a.DB.QueryRow(ctx, "SELECT provider,credentials FROM cloud_accounts WHERE id=$1", alibabaAccount).Scan(&alibabaProvider, &alibabaCipher); err != nil || alibabaProvider != "alibaba" || strings.Contains(alibabaCipher, "alibaba-secret") {
		t.Fatalf("Alibaba connection was not stored safely: provider=%q err=%v", alibabaProvider, err)
	}
	request("POST", "/api/v1/accounts", adminToken, map[string]any{"name": "Invalid Alibaba", "provider": "alibaba", "regions": []string{"not a region"}, "credentials": map[string]string{"access_key_id": "key", "secret_access_key": "secret"}}, 400)
	cloudUUID := "11111111-1111-4111-8111-111111111111"
	proveConnection("testadmin@example.com", "azure", Credentials{TenantID: cloudUUID, ClientID: cloudUUID, ClientSecret: "azure-secret", SubscriptionID: cloudUUID})
	azureAccount := idFrom(request("POST", "/api/v1/accounts", adminToken, map[string]any{"name": "Azure Production", "provider": "azure", "owner": "Platform", "group_id": group2, "regions": []string{"eastus"}, "credentials": map[string]string{"tenant_id": cloudUUID, "client_id": cloudUUID, "client_secret": "azure-secret", "subscription_id": cloudUUID}}, 200))
	gcpKey := validGCPServiceAccountJSON(t)
	proveConnection("testadmin@example.com", "gcp", Credentials{ProjectID: "example-project", ServiceAccountJSON: gcpKey})
	gcpAccount := idFrom(request("POST", "/api/v1/accounts", adminToken, map[string]any{"name": "GCP Production", "provider": "gcp", "owner": "Platform", "group_id": group2, "regions": []string{"europe-west1"}, "credentials": map[string]string{"project_id": "example-project", "service_account_json": gcpKey}}, 200))
	for _, providerAccount := range []struct {
		id       int64
		provider string
		secret   string
	}{{azureAccount, "azure", "azure-secret"}, {gcpAccount, "gcp", "PRIVATE KEY"}} {
		var provider, encrypted string
		if err = a.DB.QueryRow(ctx, "SELECT provider,credentials FROM cloud_accounts WHERE id=$1", providerAccount.id).Scan(&provider, &encrypted); err != nil || provider != providerAccount.provider || strings.Contains(encrypted, providerAccount.secret) {
			t.Fatalf("%s connection was not stored safely: provider=%q err=%v", providerAccount.provider, provider, err)
		}
		request("DELETE", fmt.Sprintf("/api/v1/accounts/%d", providerAccount.id), adminToken, nil, 200)
	}
	request("POST", "/api/v1/auth/signup", "", map[string]string{"workspace": "Independent Lab", "username": "second-owner", "email": "second-owner@example.com", "password": "Second-owner-password1!"}, http.StatusAccepted)
	request("POST", "/api/v1/auth/login", "", map[string]string{"email": "second-owner@example.com", "password": "Second-owner-password1!"}, 403)
	verifyLatest()
	secondOwner := login("second-owner@example.com", "Second-owner-password1!")
	secondGroup := idFrom(request("POST", "/api/v1/groups", secondOwner, map[string]any{"name": "Team A", "view_dashboard": true}, 200))
	proveConnection("second-owner@example.com", "aws", Credentials{AccessKey: "tenant-two", SecretKey: "isolated-secret"})
	secondAccount := idFrom(request("POST", "/api/v1/accounts", secondOwner, map[string]any{"name": "Account A", "provider": "aws", "group_id": secondGroup, "regions": []string{"us-east-1"}, "credentials": map[string]string{"access_key_id": "tenant-two", "secret_access_key": "isolated-secret"}}, 200))
	var i1, i2 int64
	for _, p := range []struct {
		account int64
		id      *int64
	}{{account1, &i1}, {account2, &i2}} {
		if err = a.DB.QueryRow(ctx, "INSERT INTO instances(account_id,instance_id,region,state,instance_type) VALUES($1,$2,'us-east-1','running','t3.micro') RETURNING id", p.account, fmt.Sprint("i-", p.account)).Scan(p.id); err != nil {
			t.Fatal(err)
		}
	}
	var secondInstance int64
	if err = a.DB.QueryRow(ctx, "INSERT INTO instances(account_id,instance_id,region,state,instance_type) VALUES($1,'i-tenant-two','us-east-1','running','t3.nano') RETURNING id", secondAccount).Scan(&secondInstance); err != nil {
		t.Fatal(err)
	}
	request("GET", fmt.Sprintf("/api/v1/instances/%d", secondInstance), adminToken, nil, 404)
	tenantCheck := request("GET", "/api/v1/accounts", adminToken, nil, 200)
	if strings.Contains(tenantCheck.Body.String(), "tenant-two") || strings.Count(tenantCheck.Body.String(), `"name":"Account A"`) != 1 {
		t.Fatal("cross-workspace account data leaked")
	}
	tenantCheck = request("GET", "/api/v1/activity", secondOwner, nil, 200)
	if strings.Contains(tenantCheck.Body.String(), "testadmin") {
		t.Fatal("cross-workspace audit data leaked")
	}
	viewer := login("viewer@example.com", "Viewer-password1!")
	w := request("GET", "/api/v1/accounts", viewer, nil, 200)
	if strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), "credentials") || strings.Contains(w.Body.String(), "Account B") || strings.Contains(w.Body.String(), "Alibaba Production") {
		t.Fatal("account data leakage")
	}
	w = request("GET", "/api/v1/instances", viewer, nil, 200)
	var list struct {
		Data []any `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list.Data) != 1 {
		t.Fatalf("expected 1 scoped instance, got %d", len(list.Data))
	}
	w = request("GET", fmt.Sprintf("/api/v1/instances?account_id=%d", account1), viewer, nil, 200)
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list.Data) != 1 {
		t.Fatalf("expected one instance in selected account, got %d", len(list.Data))
	}
	request("GET", fmt.Sprintf("/api/v1/instances?account_id=%d", account2), viewer, nil, 403)
	request("GET", fmt.Sprintf("/api/v1/summary?account_id=%d", account1), viewer, nil, 200)
	request("GET", fmt.Sprintf("/api/v1/accounts/%d/eds/desktops?region=us-east-1", account1), adminToken, nil, 400)
	if err = a.Redis.Set(ctx, edsRegionsCacheKey(workspaceID, alibabaAccount), `{"data":[{"id":"ap-southeast-1","name":"Singapore","desktops":0,"available":true},{"id":"cn-hangzhou","name":"China (Hangzhou)","desktops":3,"available":true}],"total_desktops":3}`, time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	regionIndex := request("GET", fmt.Sprintf("/api/v1/accounts/%d/eds/regions", alibabaAccount), adminToken, nil, 200)
	if !strings.Contains(regionIndex.Body.String(), `"total_desktops":3`) || !strings.Contains(regionIndex.Body.String(), "ap-southeast-1") {
		t.Fatalf("unexpected cached EDS region index: %s", regionIndex.Body.String())
	}
	request("POST", fmt.Sprintf("/api/v1/accounts/%d/eds/desktops?region=cn-hangzhou", alibabaAccount), viewer, map[string]any{}, 403)
	request("POST", fmt.Sprintf("/api/v1/accounts/%d/eds/desktops?region=cn-hangzhou", alibabaAccount), adminToken, map[string]any{"name": "desktop", "confirm_cost": false}, 400)
	request("POST", fmt.Sprintf("/api/v1/accounts/%d/eds/desktops/ecd-one/policy?region=cn-hangzhou", alibabaAccount), adminToken, map[string]any{"policy_group_id": ""}, 400)
	request("POST", fmt.Sprintf("/api/v1/accounts/%d/eds/desktops/ecd-one/maintenance?region=cn-hangzhou", alibabaAccount), adminToken, map[string]any{"mode": "INVALID"}, 400)
	request("POST", fmt.Sprintf("/api/v1/accounts/%d/eds/desktops/ecd-one/commands?region=cn-hangzhou", alibabaAccount), adminToken, map[string]any{"command": "Get-Date", "command_type": "RunPowerShellScript", "timeout": 300, "confirm": false}, 400)
	request("POST", fmt.Sprintf("/api/v1/accounts/%d/eds/desktops/ecd-one/billing?region=cn-hangzhou", alibabaAccount), adminToken, map[string]any{"charge_type": "PrePaid", "period": 4, "period_unit": "Month", "confirm_cost": true}, 400)
	request("GET", fmt.Sprintf("/api/v1/instances/%d", i1), viewer, nil, 200)
	request("GET", fmt.Sprintf("/api/v1/instances/%d", i2), viewer, nil, 403)
	request("POST", fmt.Sprintf("/api/v1/instances/%d/actions", i1), viewer, map[string]string{"action": "stop"}, 403)
	request("POST", fmt.Sprintf("/api/v1/instances/%d/actions", i1), adminToken, map[string]string{"action": "terminate"}, 400)
	request("GET", "/api/v1/users", viewer, nil, 403)
	request("GET", "/api/v1/activity", viewer, nil, 403)
	request("POST", "/api/v1/collector/run", viewer, map[string]any{}, 403)
	request("PUT", fmt.Sprintf("/api/v1/groups/%d/members/%d", group1, uid), viewer, map[string]string{"role": "manager"}, 403)
	w = request("GET", "/api/v1/summary", viewer, nil, 200)
	if !strings.Contains(w.Body.String(), `"instances":1`) {
		t.Fatal(w.Body.String())
	}
	request("PUT", fmt.Sprintf("/api/v1/groups/%d/members/%d", group1, uid), adminToken, map[string]string{"role": "manager"}, 200)
	// A group manager may not move credentials to a group they do not manage.
	request("PUT", fmt.Sprintf("/api/v1/accounts/%d", account1), viewer, map[string]any{"name": "Moved", "group_id": group2, "regions": []string{}}, 403)
	request("PUT", fmt.Sprintf("/api/v1/accounts/%d", account1), viewer, map[string]any{"name": "Renamed A", "group_id": group1, "regions": []string{}}, 200)
	var cipher string
	if err = a.DB.QueryRow(ctx, "SELECT credentials FROM cloud_accounts WHERE id=$1", account1).Scan(&cipher); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cipher, "secret-must-not-leak") {
		t.Fatal("plaintext credential stored")
	}
	plain, err := a.Vault.Decrypt(cipher)
	if err != nil || !strings.Contains(plain, "secret-must-not-leak") {
		t.Fatal("credential preservation failed")
	}
	r := httptest.NewRequest("POST", "/api/v1/collector/run", strings.NewReader("{}"))
	r.Header.Set("Origin", "https://attacker.invalid")
	r.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross-origin mutation allowed")
	}
	request("PUT", fmt.Sprintf("/api/v1/users/%d", uid), adminToken, map[string]string{"username": "viewer", "email": "viewer@example.com", "password": "Changed-password1!", "role": "user"}, 200)
	request("GET", "/api/v1/auth/me", viewer, nil, 401)
	request("PUT", "/api/v1/settings", adminToken, map[string]int{"collector_interval_minutes": 0, "audit_retention_days": 90}, 400)
	request("POST", "/api/v1/collector/run", adminToken, map[string]any{}, 202)
	if n, _ := a.Redis.Exists(ctx, collectorKey("requested", workspaceID)).Result(); n != 1 {
		t.Fatal("collection not queued")
	}
	// AWS mutations fail closed when their mandatory intent audit cannot be stored.
	if _, err = a.DB.Exec(ctx, "ALTER TABLE audit_log RENAME TO audit_log_unavailable"); err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest("POST", fmt.Sprintf("/api/v1/instances/%d/actions", i1), strings.NewReader(`{"action":"stop"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	restoreErr := func() error {
		_, restoreErr := a.DB.Exec(ctx, "ALTER TABLE audit_log_unavailable RENAME TO audit_log")
		return restoreErr
	}()
	if restoreErr != nil {
		t.Fatal(restoreErr)
	}
	if w.Code != 503 {
		t.Fatalf("AWS action did not fail closed when audit storage was unavailable: %d %s", w.Code, w.Body.String())
	}
	for i := 0; i < 4; i++ {
		request("POST", "/api/v1/users", adminToken, map[string]string{"username": fmt.Sprintf("member-%d", i), "email": fmt.Sprintf("member-%d@example.com", i), "password": "Member-password1!", "role": "user"}, 200)
	}
	request("POST", "/api/v1/users", adminToken, map[string]string{"username": "member-over-limit", "email": "member-over-limit@example.com", "password": "Member-password1!", "role": "user"}, 409)
	// An existing collector lease prevents an overlapping run, with no AWS call.
	a.Redis.Set(ctx, collectorKey("lock", workspaceID), "other-worker", time.Minute)
	if err = a.Collect(ctx, workspaceID); err != nil {
		t.Fatal(err)
	}
	if value, _ := a.Redis.Get(ctx, collectorKey("lock", workspaceID)).Result(); value != "other-worker" {
		t.Fatal("another worker's lock changed")
	}
	a.Redis.Del(ctx, collectorKey("lock", workspaceID))
	request("DELETE", fmt.Sprintf("/api/v1/accounts/%d", account1), adminToken, nil, 200)
	request("DELETE", fmt.Sprintf("/api/v1/accounts/%d", account2), adminToken, nil, 200)
	if err = a.Collect(ctx, workspaceID); err != nil {
		t.Fatal(err)
	}
	request("POST", "/api/v1/auth/logout", adminToken, map[string]any{}, 200)
	request("GET", "/api/v1/auth/me", adminToken, nil, 401)
	request("GET", "/readyz", "", nil, 200)
	request("GET", "/", "", nil, 200)
	webAsset := request("GET", "/app.js", "", nil, 200)
	if webAsset.Header().Get("Cache-Control") != "no-cache" || !strings.Contains(webAsset.Body.String(), "All available regions") || !strings.Contains(webAsset.Body.String(), "Visual mode") {
		t.Fatalf("updated service controls are not exposed safely: cache=%q", webAsset.Header().Get("Cache-Control"))
	}
	// Rate limiting is atomic and independent of email.
	for i := 0; i < 21; i++ {
		r := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"email":"none@example.com","password":"bad"}`))
		r.RemoteAddr = "198.51.100.42:1234"
		r.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if i == 20 && w.Code != 429 {
			t.Fatal("login rate limit not enforced")
		}
	}
}
