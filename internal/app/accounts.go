package app

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

type Credentials struct {
	AccessKey          string `json:"access_key_id,omitempty"`
	SecretKey          string `json:"secret_access_key,omitempty"`
	SessionToken       string `json:"session_token,omitempty"`
	TenantID           string `json:"tenant_id,omitempty"`
	ClientID           string `json:"client_id,omitempty"`
	ClientSecret       string `json:"client_secret,omitempty"`
	SubscriptionID     string `json:"subscription_id,omitempty"`
	ProjectID          string `json:"project_id,omitempty"`
	ServiceAccountJSON string `json:"service_account_json,omitempty"`
}
type accountInput struct {
	Name        string       `json:"name"`
	Provider    string       `json:"provider"`
	Owner       string       `json:"owner"`
	GroupID     *int64       `json:"group_id"`
	Regions     []string     `json:"regions"`
	Credentials *Credentials `json:"credentials"`
}

var (
	regionPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	uuidPattern       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	gcpProjectPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
)

func (a *App) accounts(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	a.list(w, r, `SELECT row_to_json(t) FROM (SELECT a.id,a.name,a.provider,a.owner,a.group_id,g.name AS group_name,a.regions,ARRAY(SELECT DISTINCT i.region FROM instances i WHERE i.account_id=a.id ORDER BY i.region) AS discovered_regions,a.last_sync_at,a.sync_error,a.sync_error_code,a.created_at,(SELECT count(*) FROM instances i WHERE i.account_id=a.id) AS instance_count FROM cloud_accounts a LEFT JOIN access_groups g ON g.id=a.group_id WHERE `+scopeSQL+` OR (a.workspace_id=$3 AND EXISTS(SELECT 1 FROM user_groups ug JOIN access_groups mg ON mg.id=ug.group_id WHERE ug.user_id=$2 AND ug.group_id=a.group_id AND ug.role='manager' AND mg.manage_cloud_accounts)) ORDER BY a.name) t`, u.Role == "admin", u.ID, u.WorkspaceID)
}
func (a *App) saveAccount(w http.ResponseWriter, r *http.Request) {
	var in accountInput
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Provider = strings.ToLower(strings.TrimSpace(in.Provider))
	if in.Provider != "" && in.Provider != "aws" && in.Provider != "alibaba" && in.Provider != "azure" && in.Provider != "gcp" {
		problem(w, 400, "Provider must be aws, alibaba, azure or gcp")
		return
	}
	if len(in.Name) < 1 || len(in.Name) > 100 || len(in.Regions) > 40 {
		problem(w, 400, "Provide a name and at most 40 regions")
		return
	}
	for _, v := range in.Regions {
		if !regionPattern.MatchString(v) {
			problem(w, 400, "Invalid cloud region")
			return
		}
	}
	var id int64
	var ok bool
	var cipher string
	var existingProvider string
	var verifiedCredentials Credentials
	if r.Method == "PUT" {
		id, ok = pathID(w, r, "id")
		if !ok {
			return
		}
		if !a.accountAccess(r, id, "manage") {
			problem(w, 403, "Account management access required")
			return
		}
		if err := a.DB.QueryRow(r.Context(), "SELECT credentials,provider FROM cloud_accounts WHERE id=$1 AND workspace_id=$2", id, current(r).WorkspaceID).Scan(&cipher, &existingProvider); err != nil {
			dbError(w, err)
			return
		}
	}
	if in.Provider == "" {
		in.Provider = existingProvider
		if in.Provider == "" {
			in.Provider = "aws"
		}
	}
	if current(r).Role != "admin" && (in.GroupID == nil || !a.groupAccess(r, *in.GroupID, "accounts")) {
		problem(w, 403, "Permission required for destination group")
		return
	}
	if in.Credentials != nil {
		if err := validateCredentials(in.Provider, in.Credentials); err != "" {
			problem(w, 400, err)
			return
		}
		b, _ := json.Marshal(in.Credentials)
		cipher = a.Vault.Encrypt(string(b))
		verifiedCredentials = *in.Credentials
	}
	if existingProvider != "" && existingProvider != in.Provider && in.Credentials == nil {
		problem(w, 400, "New credentials are required when changing provider")
		return
	}
	if cipher == "" {
		problem(w, 400, "Cloud credentials are required")
		return
	}
	credentialsChanged := id == 0 || in.Credentials != nil || existingProvider != in.Provider
	if credentialsChanged && !a.requireConnectionProof(r.Context(), current(r), in.Provider, id, verifiedCredentials) {
		codedProblem(w, 409, "NX-CONNECTION-TEST-REQUIRED", "Test this cloud connection successfully before saving", []string{"Run Test connection with the current provider and credentials", "Save within ten minutes of a successful test"})
		return
	}
	if in.Regions == nil {
		in.Regions = []string{}
	}
	var err error
	if id == 0 {
		err = a.DB.QueryRow(r.Context(), "INSERT INTO cloud_accounts(workspace_id,name,provider,owner,group_id,credentials,regions) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id", current(r).WorkspaceID, in.Name, in.Provider, in.Owner, in.GroupID, cipher, in.Regions).Scan(&id)
	} else {
		tx, beginErr := a.DB.Begin(r.Context())
		if beginErr != nil {
			dbError(w, beginErr)
			return
		}
		defer tx.Rollback(r.Context())
		_, err = tx.Exec(r.Context(), "UPDATE cloud_accounts SET name=$1,provider=$2,owner=$3,group_id=$4,credentials=$5,regions=$6,last_sync_at=CASE WHEN $9 THEN NULL ELSE last_sync_at END,sync_error=CASE WHEN $9 THEN '' ELSE sync_error END,sync_error_code=CASE WHEN $9 THEN '' ELSE sync_error_code END WHERE id=$7 AND workspace_id=$8", in.Name, in.Provider, in.Owner, in.GroupID, cipher, in.Regions, id, current(r).WorkspaceID, credentialsChanged)
		if err == nil && existingProvider != in.Provider {
			_, err = tx.Exec(r.Context(), "DELETE FROM instances WHERE account_id=$1", id)
		}
		if err == nil {
			err = tx.Commit(r.Context())
		}
	}
	if err != nil {
		dbError(w, err)
		return
	}
	a.audit(r, "account.saved", strconv.FormatInt(id, 10), map[string]string{"name": in.Name, "provider": in.Provider})
	write(w, 200, map[string]any{"id": id})
}

func validateCredentials(provider string, c *Credentials) string {
	switch provider {
	case "aws", "alibaba":
		c.AccessKey, c.SecretKey, c.SessionToken = strings.TrimSpace(c.AccessKey), strings.TrimSpace(c.SecretKey), strings.TrimSpace(c.SessionToken)
		if c.AccessKey == "" || c.SecretKey == "" {
			return "AccessKey ID and secret are required"
		}
	case "azure":
		c.TenantID, c.ClientID = strings.TrimSpace(c.TenantID), strings.TrimSpace(c.ClientID)
		c.SubscriptionID, c.ClientSecret = strings.TrimSpace(c.SubscriptionID), strings.TrimSpace(c.ClientSecret)
		if !uuidPattern.MatchString(c.TenantID) || !uuidPattern.MatchString(c.ClientID) || !uuidPattern.MatchString(c.SubscriptionID) || c.ClientSecret == "" || len(c.ClientSecret) > 1024 {
			return "Azure tenant, client and subscription IDs must be UUIDs, and the client secret is required"
		}
	case "gcp":
		c.ProjectID, c.ServiceAccountJSON = strings.TrimSpace(c.ProjectID), strings.TrimSpace(c.ServiceAccountJSON)
		var key struct {
			Type        string `json:"type"`
			ClientEmail string `json:"client_email"`
			PrivateKey  string `json:"private_key"`
			TokenURI    string `json:"token_uri"`
		}
		if json.Unmarshal([]byte(c.ServiceAccountJSON), &key) != nil {
			return "A valid GCP project ID and Google service-account JSON key are required"
		}
		block, _ := pem.Decode([]byte(key.PrivateKey))
		validKey := block != nil && block.Type == "PRIVATE KEY"
		if validKey {
			_, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
			validKey = parseErr == nil
		}
		if !gcpProjectPattern.MatchString(c.ProjectID) || key.Type != "service_account" || key.ClientEmail == "" || key.TokenURI != "https://oauth2.googleapis.com/token" || !validKey {
			return "A valid GCP project ID and Google service-account JSON key are required"
		}
	default:
		return "Unsupported cloud provider"
	}
	return ""
}

func (a *App) deleteAccount(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if !a.accountAccess(r, id, "manage") {
		problem(w, 403, "Account management access required")
		return
	}
	tag, err := a.DB.Exec(r.Context(), "DELETE FROM cloud_accounts WHERE id=$1 AND workspace_id=$2", id, current(r).WorkspaceID)
	if err != nil {
		dbError(w, err)
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, 404, "Account not found")
		return
	}
	a.audit(r, "account.deleted", r.PathValue("id"), nil)
	write(w, 200, map[string]bool{"ok": true})
}
