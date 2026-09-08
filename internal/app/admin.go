package app

import (
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strconv"
	"strings"
)

func (a *App) groups(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	a.list(w, r, `SELECT row_to_json(t) FROM (SELECT g.*, (SELECT count(*) FROM user_groups ug WHERE ug.group_id=g.id) AS member_count FROM access_groups g WHERE g.workspace_id=$3 AND ($1 OR EXISTS(SELECT 1 FROM user_groups ug WHERE ug.group_id=g.id AND ug.user_id=$2)) ORDER BY g.name) t`, u.Role == "admin", u.ID, u.WorkspaceID)
}
func (a *App) saveGroup(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	var in struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		View        bool   `json:"view_dashboard"`
		Accounts    bool   `json:"manage_cloud_accounts"`
		Members     bool   `json:"manage_group_members"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if len(in.Name) < 1 || len(in.Name) > 100 {
		problem(w, 400, "Name must be 1–100 characters")
		return
	}
	var id int64
	var err error
	if r.Method == "POST" {
		err = a.DB.QueryRow(r.Context(), "INSERT INTO access_groups(workspace_id,name,description,view_dashboard,manage_cloud_accounts,manage_group_members) VALUES($1,$2,$3,$4,$5,$6) RETURNING id", current(r).WorkspaceID, in.Name, in.Description, in.View, in.Accounts, in.Members).Scan(&id)
	} else {
		var ok bool
		id, ok = pathID(w, r, "id")
		if !ok {
			return
		}
		err = a.DB.QueryRow(r.Context(), "UPDATE access_groups SET name=$1,description=$2,view_dashboard=$3,manage_cloud_accounts=$4,manage_group_members=$5 WHERE id=$6 AND workspace_id=$7 RETURNING id", in.Name, in.Description, in.View, in.Accounts, in.Members, id, current(r).WorkspaceID).Scan(&id)
	}
	if err != nil {
		dbError(w, err)
		return
	}
	a.audit(r, "group.saved", strconv.FormatInt(id, 10), in)
	write(w, 200, map[string]int64{"id": id})
}
func (a *App) deleteGroup(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	tag, err := a.DB.Exec(r.Context(), "DELETE FROM access_groups WHERE id=$1 AND workspace_id=$2", id, current(r).WorkspaceID)
	if err != nil {
		dbError(w, err)
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, 404, "Group not found")
		return
	}
	a.audit(r, "group.deleted", r.PathValue("id"), nil)
	write(w, 200, map[string]bool{"ok": true})
}
func (a *App) users(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	u := current(r)
	a.list(w, r, "SELECT row_to_json(t) FROM (SELECT u.id,u.username,u.role,u.is_owner,u.created_at,w.user_limit,(SELECT count(*) FROM users own WHERE own.workspace_id=u.workspace_id) AS workspace_user_count FROM users u JOIN workspaces w ON w.id=u.workspace_id WHERE u.workspace_id=$1 ORDER BY u.is_owner DESC,u.username) t", u.WorkspaceID)
}
func (a *App) saveUser(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if len(in.Username) < 3 || len(in.Username) > 100 || (in.Role != "admin" && in.Role != "user") {
		problem(w, 400, "Username must be 3–100 characters; role must be admin or user")
		return
	}
	if (r.Method == "POST" || in.Password != "") && (len(in.Password) < 12 || len(in.Password) > 72) {
		problem(w, 400, "Password must be 12–72 bytes")
		return
	}
	var hash string
	if in.Password != "" {
		b, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
		if err != nil {
			dbError(w, err)
			return
		}
		hash = string(b)
	}
	var id int64
	var err error
	if r.Method == "POST" {
		tx, beginErr := a.DB.Begin(r.Context())
		if beginErr != nil {
			dbError(w, beginErr)
			return
		}
		defer tx.Rollback(r.Context())
		if _, err = tx.Exec(r.Context(), "SELECT pg_advisory_xact_lock($1)", current(r).WorkspaceID); err == nil {
			var count, limit int
			err = tx.QueryRow(r.Context(), "SELECT count(*),max(w.user_limit) FROM users u JOIN workspaces w ON w.id=u.workspace_id WHERE u.workspace_id=$1", current(r).WorkspaceID).Scan(&count, &limit)
			if err == nil && count >= limit {
				problem(w, 409, "Community workspaces can add up to five team members")
				return
			}
		}
		if err == nil {
			err = tx.QueryRow(r.Context(), "INSERT INTO users(workspace_id,username,password_hash,role) VALUES($1,$2,$3,$4) RETURNING id", current(r).WorkspaceID, in.Username, hash, in.Role).Scan(&id)
		}
		if err == nil {
			err = tx.Commit(r.Context())
		}
	} else {
		var ok bool
		id, ok = pathID(w, r, "id")
		if !ok {
			return
		}
		var isOwner bool
		if err = a.DB.QueryRow(r.Context(), "SELECT is_owner FROM users WHERE id=$1 AND workspace_id=$2", id, current(r).WorkspaceID).Scan(&isOwner); err != nil {
			dbError(w, err)
			return
		}
		if isOwner && in.Role != "admin" {
			problem(w, 400, "The workspace owner must remain an administrator")
			return
		}
		if id == current(r).ID && in.Role != "admin" {
			problem(w, 400, "You cannot demote your own administrator account")
			return
		}
		err = a.DB.QueryRow(r.Context(), "UPDATE users SET username=$1,password_hash=CASE WHEN $2='' THEN password_hash ELSE $2 END,role=$3,session_version=session_version+1 WHERE id=$4 AND workspace_id=$5 RETURNING id", in.Username, hash, in.Role, id, current(r).WorkspaceID).Scan(&id)
	}
	if err != nil {
		dbError(w, err)
		return
	}
	a.audit(r, "user.saved", strconv.FormatInt(id, 10), map[string]string{"username": in.Username, "role": in.Role})
	write(w, 200, map[string]int64{"id": id})
}
func (a *App) deleteUser(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if id == current(r).ID {
		problem(w, 400, "You cannot delete your own account")
		return
	}
	tag, err := a.DB.Exec(r.Context(), "DELETE FROM users WHERE id=$1 AND workspace_id=$2 AND NOT is_owner", id, current(r).WorkspaceID)
	if err != nil {
		dbError(w, err)
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, 404, "User not found")
		return
	}
	a.audit(r, "user.deleted", r.PathValue("id"), nil)
	write(w, 200, map[string]bool{"ok": true})
}
func (a *App) memberships(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	a.list(w, r, `SELECT row_to_json(t) FROM (SELECT ug.*,u.username,g.name AS group_name FROM user_groups ug JOIN users u ON u.id=ug.user_id JOIN access_groups g ON g.id=ug.group_id WHERE g.workspace_id=$3 AND ($1 OR ug.user_id=$2 OR EXISTS(SELECT 1 FROM user_groups own WHERE own.user_id=$2 AND own.group_id=g.id AND own.role='manager' AND g.manage_group_members)) ORDER BY g.name,u.username) t`, u.Role == "admin", u.ID, u.WorkspaceID)
}
func (a *App) saveMembership(w http.ResponseWriter, r *http.Request) {
	gid, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	uid, ok := pathID(w, r, "userID")
	if !ok {
		return
	}
	if !a.groupAccess(r, gid, "members") {
		problem(w, 403, "Group membership management access required")
		return
	}
	var in struct {
		Role string `json:"role"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Role != "viewer" && in.Role != "operator" && in.Role != "manager" {
		problem(w, 400, "Role must be viewer, operator or manager")
		return
	}
	tag, err := a.DB.Exec(r.Context(), "INSERT INTO user_groups(user_id,group_id,role) SELECT u.id,g.id,$3 FROM users u JOIN access_groups g ON g.id=$2 WHERE u.id=$1 AND u.workspace_id=$4 AND g.workspace_id=$4 ON CONFLICT(user_id,group_id) DO UPDATE SET role=excluded.role", uid, gid, in.Role, current(r).WorkspaceID)
	if err != nil {
		dbError(w, err)
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, 404, "User or group not found in this workspace")
		return
	}
	a.audit(r, "membership.saved", r.PathValue("id")+"/"+r.PathValue("userID"), in)
	write(w, 200, map[string]bool{"ok": true})
}
func (a *App) deleteMembership(w http.ResponseWriter, r *http.Request) {
	gid, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	uid, ok := pathID(w, r, "userID")
	if !ok {
		return
	}
	if !a.groupAccess(r, gid, "members") {
		problem(w, 403, "Group membership management access required")
		return
	}
	_, err := a.DB.Exec(r.Context(), "DELETE FROM user_groups ug USING access_groups g,users u WHERE ug.group_id=$1 AND ug.user_id=$2 AND g.id=ug.group_id AND u.id=ug.user_id AND g.workspace_id=$3 AND u.workspace_id=$3", gid, uid, current(r).WorkspaceID)
	if err != nil {
		dbError(w, err)
		return
	}
	a.audit(r, "membership.deleted", r.PathValue("id")+"/"+r.PathValue("userID"), nil)
	write(w, 200, map[string]bool{"ok": true})
}
func (a *App) activity(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	limit, offset := pagination(r)
	a.list(w, r, "SELECT row_to_json(t) FROM (SELECT id,user_id,username,action,target,details,created_at FROM audit_log WHERE workspace_id=$1 AND ($2='' OR action ILIKE '%'||$2||'%' OR username ILIKE '%'||$2||'%' OR target ILIKE '%'||$2||'%') ORDER BY id DESC LIMIT $3 OFFSET $4) t", current(r).WorkspaceID, r.URL.Query().Get("q"), limit, offset)
}
func (a *App) settings(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	a.list(w, r, "SELECT row_to_json(t) FROM (SELECT collector_interval_minutes,audit_retention_days,last_collector_run_at FROM settings WHERE workspace_id=$1) t", current(r).WorkspaceID)
}
func (a *App) saveSettings(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	var in struct {
		Interval  int `json:"collector_interval_minutes"`
		Retention int `json:"audit_retention_days"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Interval < 1 || in.Interval > 10080 || in.Retention < 7 || in.Retention > 3650 {
		problem(w, 400, "Interval: 1–10080 minutes; retention: 7–3650 days")
		return
	}
	_, err := a.DB.Exec(r.Context(), "UPDATE settings SET collector_interval_minutes=$1,audit_retention_days=$2 WHERE workspace_id=$3", in.Interval, in.Retention, current(r).WorkspaceID)
	if err != nil {
		dbError(w, err)
		return
	}
	a.audit(r, "settings.updated", "", in)
	write(w, 200, map[string]bool{"ok": true})
}
func pagination(r *http.Request) (int, int) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 200 {
		limit = 50
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
