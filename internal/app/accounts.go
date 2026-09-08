package app

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

type Credentials struct {
	AccessKey    string `json:"access_key_id"`
	SecretKey    string `json:"secret_access_key"`
	SessionToken string `json:"session_token,omitempty"`
}
type accountInput struct {
	Name        string       `json:"name"`
	Provider    string       `json:"provider"`
	Owner       string       `json:"owner"`
	GroupID     *int64       `json:"group_id"`
	Regions     []string     `json:"regions"`
	Credentials *Credentials `json:"credentials"`
}

var regionPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+){1,4}$`)

func (a *App) accounts(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	a.list(w, r, `SELECT row_to_json(t) FROM (SELECT a.id,a.name,a.provider,a.owner,a.group_id,g.name AS group_name,a.regions,ARRAY(SELECT DISTINCT i.region FROM instances i WHERE i.account_id=a.id ORDER BY i.region) AS discovered_regions,a.last_sync_at,a.sync_error,a.created_at,(SELECT count(*) FROM instances i WHERE i.account_id=a.id) AS instance_count FROM cloud_accounts a LEFT JOIN access_groups g ON g.id=a.group_id WHERE `+scopeSQL+` OR (a.workspace_id=$3 AND EXISTS(SELECT 1 FROM user_groups ug JOIN access_groups mg ON mg.id=ug.group_id WHERE ug.user_id=$2 AND ug.group_id=a.group_id AND ug.role='manager' AND mg.manage_cloud_accounts)) ORDER BY a.name) t`, u.Role == "admin", u.ID, u.WorkspaceID)
}
func (a *App) saveAccount(w http.ResponseWriter, r *http.Request) {
	var in accountInput
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Provider = strings.ToLower(strings.TrimSpace(in.Provider))
	if in.Provider != "" && in.Provider != "aws" && in.Provider != "alibaba" {
		problem(w, 400, "Provider must be aws or alibaba")
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
		if in.Credentials.AccessKey == "" || in.Credentials.SecretKey == "" {
			problem(w, 400, "Both AccessKey ID and AccessKey secret are required")
			return
		}
		b, _ := json.Marshal(in.Credentials)
		cipher = a.Vault.Encrypt(string(b))
	}
	if existingProvider != "" && existingProvider != in.Provider && in.Credentials == nil {
		problem(w, 400, "New credentials are required when changing provider")
		return
	}
	if cipher == "" {
		problem(w, 400, "Cloud credentials are required")
		return
	}
	if in.Regions == nil {
		in.Regions = []string{}
	}
	var err error
	if id == 0 {
		err = a.DB.QueryRow(r.Context(), "INSERT INTO cloud_accounts(workspace_id,name,provider,owner,group_id,credentials,regions) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id", current(r).WorkspaceID, in.Name, in.Provider, in.Owner, in.GroupID, cipher, in.Regions).Scan(&id)
	} else {
		_, err = a.DB.Exec(r.Context(), "UPDATE cloud_accounts SET name=$1,provider=$2,owner=$3,group_id=$4,credentials=$5,regions=$6 WHERE id=$7 AND workspace_id=$8", in.Name, in.Provider, in.Owner, in.GroupID, cipher, in.Regions, id, current(r).WorkspaceID)
	}
	if err != nil {
		dbError(w, err)
		return
	}
	a.audit(r, "account.saved", strconv.FormatInt(id, 10), map[string]string{"name": in.Name, "provider": in.Provider})
	write(w, 200, map[string]any{"id": id})
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
