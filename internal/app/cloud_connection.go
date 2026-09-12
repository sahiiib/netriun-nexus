package app

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/netriun/nexus/internal/cloud"
	"github.com/netriun/nexus/internal/secure"
)

type connectionTestInput struct {
	Provider    string       `json:"provider"`
	Credentials *Credentials `json:"credentials"`
}

func connectionProofKey(u User, provider string, accountID int64, credentials Credentials) string {
	raw, _ := json.Marshal(credentials)
	identity := strings.Join([]string{strconv.FormatInt(u.WorkspaceID, 10), strconv.FormatInt(u.ID, 10), provider, strconv.FormatInt(accountID, 10), string(raw)}, "\x00")
	return "connection-test-proof:" + secure.Digest(identity)
}

func (a *App) requireConnectionProof(ctx context.Context, u User, provider string, accountID int64, credentials Credentials) bool {
	key := connectionProofKey(u, provider, accountID, credentials)
	result, err := a.Redis.Eval(ctx, `if redis.call('GET',KEYS[1]) then redis.call('DEL',KEYS[1]); return 1 else return 0 end`, []string{key}).Int()
	return err == nil && result == 1
}

func providerErrorCode(provider string) string {
	return map[string]string{
		"aws":     "NX-AWS-CONNECTION-001",
		"alibaba": "NX-ALIBABA-CONNECTION-001",
		"azure":   "NX-AZURE-CONNECTION-001",
		"gcp":     "NX-GCP-CONNECTION-001",
	}[provider]
}

func providerFixes(provider string) []string {
	switch provider {
	case "aws":
		return []string{"Check the AccessKey ID and secret", "Allow ec2:DescribeRegions and ec2:DescribeInstances", "Check any region restrictions on the IAM policy"}
	case "alibaba":
		return []string{"Check the RAM AccessKey ID and secret", "Allow ecs:DescribeRegions and ecs:DescribeInstances", "Confirm that the RAM user is enabled"}
	case "azure":
		return []string{"Check tenant, client and subscription IDs", "Create a new client secret if it expired", "Assign Reader or Virtual Machine Contributor on the subscription"}
	case "gcp":
		return []string{"Check the project ID and service-account JSON key", "Enable the Compute Engine API", "Grant Compute Viewer or Compute Instance Admin (v1)"}
	default:
		return []string{"Check the provider credentials and permissions"}
	}
}

func codedProblem(w http.ResponseWriter, status int, code, message string, fixes []string) {
	write(w, status, map[string]any{"error": message, "code": code, "how_to_fix": fixes})
}

func (a *App) canTestNewAccount(ctx context.Context, u User) bool {
	if u.Role == "admin" {
		return true
	}
	var allowed bool
	err := a.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_groups ug JOIN access_groups g ON g.id=ug.group_id WHERE ug.user_id=$1 AND ug.role='manager' AND g.workspace_id=$2 AND g.manage_cloud_accounts)`, u.ID, u.WorkspaceID).Scan(&allowed)
	return err == nil && allowed
}

func (a *App) testCloudAccount(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	if !a.allowAttempt(r, "account-test:"+strconv.FormatInt(u.ID, 10), 20) {
		w.Header().Set("Retry-After", "300")
		problem(w, 429, "Too many connection tests; try again in five minutes")
		return
	}
	var in connectionTestInput
	if !decode(w, r, &in) {
		return
	}
	in.Provider = strings.ToLower(strings.TrimSpace(in.Provider))
	idValue := r.PathValue("id")
	var accountID int64
	var credentials Credentials
	if idValue != "" {
		var ok bool
		accountID, ok = pathID(w, r, "id")
		if !ok {
			return
		}
		if !a.accountAccess(r, accountID, "manage") {
			problem(w, 403, "Account management access required")
			return
		}
		var storedProvider, encrypted string
		if err := a.DB.QueryRow(r.Context(), "SELECT provider,credentials FROM cloud_accounts WHERE id=$1 AND workspace_id=$2", accountID, u.WorkspaceID).Scan(&storedProvider, &encrypted); err != nil {
			dbError(w, err)
			return
		}
		if in.Provider == "" {
			in.Provider = storedProvider
		}
		if in.Credentials == nil {
			if in.Provider != storedProvider {
				problem(w, 400, "New credentials are required when testing another provider")
				return
			}
			plain, err := a.Vault.Decrypt(encrypted)
			if err != nil || json.Unmarshal([]byte(plain), &credentials) != nil {
				codedProblem(w, 502, providerErrorCode(in.Provider), "Stored cloud credentials could not be read", providerFixes(in.Provider))
				return
			}
		} else {
			credentials = *in.Credentials
		}
	} else {
		if !a.canTestNewAccount(r.Context(), u) {
			problem(w, 403, "Cloud account management access required")
			return
		}
		if in.Credentials == nil {
			problem(w, 400, "Cloud credentials are required")
			return
		}
		credentials = *in.Credentials
	}
	if message := validateCredentials(in.Provider, &credentials); message != "" {
		problem(w, 400, message)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()
	var err error
	switch in.Provider {
	case "aws":
		client := cloud.Client("us-east-1", credentials.AccessKey, credentials.SecretKey, credentials.SessionToken)
		_, err = cloud.Regions(ctx, client)
		if err == nil {
			err = cloud.AWSConnection(ctx, client)
		}
	case "alibaba":
		var clientErr error
		client, clientErr := cloud.AlibabaClient("cn-hangzhou", credentials.AccessKey, credentials.SecretKey, credentials.SessionToken)
		err = clientErr
		if err == nil {
			var regions []string
			regions, err = cloud.AlibabaRegions(ctx, client)
			if err == nil {
				region := "cn-hangzhou"
				if len(regions) > 0 {
					region = regions[0]
				}
				err = cloud.AlibabaConnection(ctx, client, region)
			}
		}
	case "azure":
		var client *cloud.AzureClient
		client, err = cloud.NewAzureClient(ctx, credentials.TenantID, credentials.ClientID, credentials.ClientSecret, credentials.SubscriptionID)
		if err == nil {
			err = cloud.AzureConnection(ctx, client)
		}
	case "gcp":
		var client *cloud.GCPClient
		client, err = cloud.NewGCPClient(ctx, credentials.ProjectID, credentials.ServiceAccountJSON)
		if err == nil {
			err = cloud.GCPConnection(ctx, client)
		}
	default:
		problem(w, 400, "Provider must be aws, alibaba, azure or gcp")
		return
	}
	if err != nil {
		slog.Warn("cloud connection test failed", "provider", in.Provider, "account_id", accountID, "error", err)
		codedProblem(w, 502, providerErrorCode(in.Provider), "Cloud connection test failed", providerFixes(in.Provider))
		return
	}
	if err = a.Redis.Set(r.Context(), connectionProofKey(u, in.Provider, accountID, credentials), "1", 10*time.Minute).Err(); err != nil {
		problem(w, 503, "Connection was verified but the verification proof could not be stored; try again")
		return
	}
	_ = a.record(r.Context(), u.WorkspaceID, u.ID, u.Username, "account.connection_tested", idValue, map[string]string{"provider": in.Provider})
	write(w, 200, map[string]string{"status": "connected", "provider": in.Provider, "message": "Credentials and required read access are working"})
}
