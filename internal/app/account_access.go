package app

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

type accountAccessInput struct {
	PrincipalType string `json:"principal_type"`
	PrincipalID   int64  `json:"principal_id"`
	CloudAccount  int64  `json:"cloud_account_id"`
	RoleKey       string `json:"role_key"`
	ServiceKey    string `json:"service_key"`
}

func (a *App) accountAccessPolicy(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	u := current(r)
	rows, err := a.DB.Query(r.Context(), `
SELECT row_to_json(t) FROM (
 SELECT aa.id,aa.principal_type,COALESCE(aa.user_id,aa.group_id) AS principal_id,
  CASE WHEN aa.principal_type='user' THEN usr.username ELSE grp.name END AS principal_name,
  aa.cloud_account_id,ca.name AS cloud_account_name,aa.role_id,ar.key AS role_key,ar.name AS role_name,
  aa.service_key,aa.source_type,aa.source_ref,aa.created_at
 FROM account_access_assignments aa
 JOIN cloud_accounts ca ON ca.id=aa.cloud_account_id AND ca.workspace_id=aa.workspace_id
 JOIN access_roles ar ON ar.id=aa.role_id AND ar.workspace_id=aa.workspace_id
 LEFT JOIN users usr ON usr.id=aa.user_id
 LEFT JOIN access_groups grp ON grp.id=aa.group_id
 WHERE aa.workspace_id=$1
 ORDER BY ca.name,aa.principal_type,principal_name
) t`, u.WorkspaceID)
	if err != nil {
		dbError(w, err)
		return
	}
	assignments := []json.RawMessage{}
	for rows.Next() {
		var raw json.RawMessage
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			dbError(w, err)
			return
		}
		assignments = append(assignments, raw)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		dbError(w, err)
		return
	}
	rows.Close()

	roleRows, err := a.DB.Query(r.Context(), "SELECT id,key,name,description,permissions,built_in FROM access_roles WHERE workspace_id=$1 ORDER BY CASE key WHEN 'viewer' THEN 1 WHEN 'operator' THEN 2 WHEN 'account_manager' THEN 3 ELSE 4 END,name", u.WorkspaceID)
	if err != nil {
		dbError(w, err)
		return
	}
	roles := []map[string]any{}
	for roleRows.Next() {
		var id int64
		var key, name, description string
		var permissions []string
		var builtIn bool
		if err = roleRows.Scan(&id, &key, &name, &description, &permissions, &builtIn); err != nil {
			roleRows.Close()
			dbError(w, err)
			return
		}
		roles = append(roles, map[string]any{"id": id, "key": key, "name": name, "description": description, "permissions": permissions, "built_in": builtIn})
	}
	if err = roleRows.Err(); err != nil {
		roleRows.Close()
		dbError(w, err)
		return
	}
	roleRows.Close()

	userRows, err := a.DB.Query(r.Context(), "SELECT id,username,role FROM users WHERE workspace_id=$1 ORDER BY is_owner DESC,username", u.WorkspaceID)
	if err != nil {
		dbError(w, err)
		return
	}
	type policyUser struct {
		id       int64
		username string
		role     string
	}
	policyUsers := []policyUser{}
	for userRows.Next() {
		var item policyUser
		if err = userRows.Scan(&item.id, &item.username, &item.role); err != nil {
			userRows.Close()
			dbError(w, err)
			return
		}
		policyUsers = append(policyUsers, item)
	}
	if err = userRows.Err(); err != nil {
		userRows.Close()
		dbError(w, err)
		return
	}
	userRows.Close()
	accountRows, err := a.DB.Query(r.Context(), "SELECT id,name FROM cloud_accounts WHERE workspace_id=$1 ORDER BY name", u.WorkspaceID)
	if err != nil {
		dbError(w, err)
		return
	}
	type policyAccount struct {
		id   int64
		name string
	}
	policyAccounts := []policyAccount{}
	for accountRows.Next() {
		var item policyAccount
		if err = accountRows.Scan(&item.id, &item.name); err != nil {
			accountRows.Close()
			dbError(w, err)
			return
		}
		policyAccounts = append(policyAccounts, item)
	}
	if err = accountRows.Err(); err != nil {
		accountRows.Close()
		dbError(w, err)
		return
	}
	accountRows.Close()
	effective := []map[string]any{}
	for _, person := range policyUsers {
		identity := User{ID: person.id, WorkspaceID: u.WorkspaceID, Role: person.role}
		for _, account := range policyAccounts {
			capabilities := []string{}
			if a.Policy.CanAccount(r.Context(), identity, account.id, CapabilityAccountView) {
				capabilities = append(capabilities, string(CapabilityAccountView))
			}
			if a.Policy.CanAccount(r.Context(), identity, account.id, CapabilityComputeAction) {
				capabilities = append(capabilities, string(CapabilityComputeAction))
			}
			if a.Policy.CanAccount(r.Context(), identity, account.id, CapabilityAccountManage) {
				capabilities = append(capabilities, string(CapabilityAccountManage))
			}
			role := "none"
			if person.role == "admin" {
				role = "workspace_admin"
			} else if containsCapability(capabilities, CapabilityAccountManage) {
				role = "account_manager"
			} else if containsCapability(capabilities, CapabilityComputeAction) {
				role = "operator"
			} else if containsCapability(capabilities, CapabilityAccountView) {
				role = "viewer"
			}
			effective = append(effective, map[string]any{"user_id": person.id, "username": person.username, "cloud_account_id": account.id, "cloud_account_name": account.name, "role_key": role, "capabilities": capabilities})
		}
	}
	write(w, 200, map[string]any{"assignments": assignments, "roles": roles, "effective": effective})
}

func containsCapability(values []string, capability Capability) bool {
	for _, value := range values {
		if value == string(capability) {
			return true
		}
	}
	return false
}

func (a *App) saveAccountAccess(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	var in accountAccessInput
	if !decode(w, r, &in) {
		return
	}
	in.PrincipalType = strings.ToLower(strings.TrimSpace(in.PrincipalType))
	in.RoleKey = strings.ToLower(strings.TrimSpace(in.RoleKey))
	in.ServiceKey = strings.ToLower(strings.TrimSpace(in.ServiceKey))
	if in.ServiceKey == "" {
		in.ServiceKey = "*"
	}
	if (in.PrincipalType != "user" && in.PrincipalType != "team") || in.PrincipalID < 1 || in.CloudAccount < 1 || in.ServiceKey != "*" {
		problem(w, 400, "Choose a valid user or team, cloud account, and account-level scope")
		return
	}
	u := current(r)
	tx, err := a.DB.Begin(r.Context())
	if err != nil {
		dbError(w, err)
		return
	}
	defer tx.Rollback(r.Context())
	if _, err = tx.Exec(r.Context(), "SELECT pg_advisory_xact_lock($1,$2)", u.WorkspaceID, in.CloudAccount); err != nil {
		dbError(w, err)
		return
	}
	var principalExists, accountExists bool
	if in.PrincipalType == "user" {
		err = tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND workspace_id=$2)", in.PrincipalID, u.WorkspaceID).Scan(&principalExists)
	} else {
		err = tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM access_groups WHERE id=$1 AND workspace_id=$2)", in.PrincipalID, u.WorkspaceID).Scan(&principalExists)
	}
	if err == nil {
		err = tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM cloud_accounts WHERE id=$1 AND workspace_id=$2)", in.CloudAccount, u.WorkspaceID).Scan(&accountExists)
	}
	if err != nil {
		dbError(w, err)
		return
	}
	if !principalExists || !accountExists {
		problem(w, 404, "User, team, or cloud account was not found in this workspace")
		return
	}
	var assignmentCount int
	if err = tx.QueryRow(r.Context(), "SELECT count(*) FROM account_access_assignments WHERE workspace_id=$1 AND cloud_account_id=$2", u.WorkspaceID, in.CloudAccount).Scan(&assignmentCount); err != nil {
		dbError(w, err)
		return
	}
	if assignmentCount == 0 {
		// Preserve all effective legacy access when an account opts in to the
		// explicit model. The new assignment must never silently revoke peers.
		_, err = tx.Exec(r.Context(), `
INSERT INTO account_access_assignments(workspace_id,principal_type,group_id,cloud_account_id,role_id,service_key,source_type,source_ref,created_by)
SELECT ca.workspace_id,'team',g.id,ca.id,ar.id,'*','manual','legacy-migration',$3
FROM cloud_accounts ca
JOIN access_groups g ON g.id=ca.group_id AND g.workspace_id=ca.workspace_id
JOIN access_roles ar ON ar.workspace_id=ca.workspace_id AND ar.key=CASE WHEN g.manage_cloud_accounts THEN 'account_manager' ELSE 'operator' END
WHERE ca.workspace_id=$1 AND ca.id=$2 AND g.view_dashboard
ON CONFLICT DO NOTHING`, u.WorkspaceID, in.CloudAccount, u.ID)
		if err == nil {
			_, err = tx.Exec(r.Context(), `
INSERT INTO account_access_assignments(workspace_id,principal_type,user_id,cloud_account_id,role_id,service_key,source_type,source_ref,created_by)
SELECT ca.workspace_id,'user',ug.user_id,ca.id,ar.id,'*','manual','legacy-migration',$3
FROM cloud_accounts ca
JOIN access_groups g ON g.id=ca.group_id AND g.workspace_id=ca.workspace_id
JOIN user_groups ug ON ug.group_id=g.id AND ug.role='manager'
JOIN access_roles ar ON ar.workspace_id=ca.workspace_id AND ar.key='account_manager'
WHERE ca.workspace_id=$1 AND ca.id=$2 AND NOT g.view_dashboard AND g.manage_cloud_accounts
ON CONFLICT DO NOTHING`, u.WorkspaceID, in.CloudAccount, u.ID)
		}
		if err != nil {
			dbError(w, err)
			return
		}
	}
	if in.PrincipalType == "user" {
		_, err = tx.Exec(r.Context(), "DELETE FROM account_access_assignments WHERE workspace_id=$1 AND principal_type='user' AND user_id=$2 AND cloud_account_id=$3 AND service_key=$4 AND source_type='manual'", u.WorkspaceID, in.PrincipalID, in.CloudAccount, in.ServiceKey)
	} else {
		_, err = tx.Exec(r.Context(), "DELETE FROM account_access_assignments WHERE workspace_id=$1 AND principal_type='team' AND group_id=$2 AND cloud_account_id=$3 AND service_key=$4 AND source_type='manual'", u.WorkspaceID, in.PrincipalID, in.CloudAccount, in.ServiceKey)
	}
	if err != nil {
		dbError(w, err)
		return
	}
	var id int64
	if in.RoleKey != "" && in.RoleKey != "none" {
		var roleID int64
		if err = tx.QueryRow(r.Context(), "SELECT id FROM access_roles WHERE workspace_id=$1 AND key=$2", u.WorkspaceID, in.RoleKey).Scan(&roleID); err != nil {
			problem(w, 400, "Choose a valid access role")
			return
		}
		if in.PrincipalType == "user" {
			err = tx.QueryRow(r.Context(), `INSERT INTO account_access_assignments(workspace_id,principal_type,user_id,cloud_account_id,role_id,service_key,source_type,created_by) VALUES($1,'user',$2,$3,$4,$5,'manual',$6) RETURNING id`, u.WorkspaceID, in.PrincipalID, in.CloudAccount, roleID, in.ServiceKey, u.ID).Scan(&id)
		} else {
			err = tx.QueryRow(r.Context(), `INSERT INTO account_access_assignments(workspace_id,principal_type,group_id,cloud_account_id,role_id,service_key,source_type,created_by) VALUES($1,'team',$2,$3,$4,$5,'manual',$6) RETURNING id`, u.WorkspaceID, in.PrincipalID, in.CloudAccount, roleID, in.ServiceKey, u.ID).Scan(&id)
		}
		if err != nil {
			dbError(w, err)
			return
		}
	}
	if err = tx.Commit(r.Context()); err != nil {
		dbError(w, err)
		return
	}
	a.audit(r, "account_access.saved", strconv.FormatInt(in.CloudAccount, 10), in)
	write(w, 200, map[string]any{"id": id, "removed": id == 0})
}
