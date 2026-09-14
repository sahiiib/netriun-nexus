package app

import (
	"context"
	"errors"
	"net/http"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Capability string

const (
	CapabilityAccountView   Capability = "account.view"
	CapabilityComputeView   Capability = "compute.view"
	CapabilityComputeAction Capability = "compute.operate"
	CapabilityAccountManage Capability = "account.manage"
)

type PolicyEngine struct {
	DB *pgxpool.Pool
}

func (p *PolicyEngine) AccessibleAccountIDs(ctx context.Context, u User, capability Capability) ([]int64, error) {
	rows, err := p.DB.Query(ctx, `
SELECT a.id FROM cloud_accounts a
WHERE a.workspace_id=$1 AND (
 $2::boolean
 OR EXISTS(
  SELECT 1
  FROM account_access_assignments aa
  JOIN access_roles ar ON ar.id=aa.role_id AND ar.workspace_id=aa.workspace_id
  LEFT JOIN user_groups ug ON aa.principal_type='team' AND ug.group_id=aa.group_id AND ug.user_id=$3
  WHERE aa.workspace_id=$1 AND aa.cloud_account_id=a.id AND aa.service_key='*'
   AND $4=ANY(ar.permissions)
   AND (
    (aa.principal_type='user' AND aa.user_id=$3)
    OR (aa.principal_type='team' AND ug.user_id IS NOT NULL AND
     CASE ug.role WHEN 'manager' THEN 3 WHEN 'operator' THEN 2 ELSE 1 END >=
     CASE $4 WHEN 'account.manage' THEN 3 WHEN 'compute.operate' THEN 2 ELSE 1 END)
   )
 )
 OR (
  NOT EXISTS(SELECT 1 FROM account_access_assignments existing WHERE existing.workspace_id=$1 AND existing.cloud_account_id=a.id)
  AND EXISTS(
   SELECT 1 FROM user_groups legacy
   JOIN access_groups g ON g.id=legacy.group_id AND g.workspace_id=$1
   WHERE legacy.user_id=$3 AND legacy.group_id=a.group_id AND (
    ($4 IN ('account.view','compute.view') AND g.view_dashboard)
    OR ($4='compute.operate' AND g.view_dashboard AND legacy.role IN ('operator','manager'))
    OR ($4='account.manage' AND g.manage_cloud_accounts AND legacy.role='manager')
   )
  )
 )
)
ORDER BY a.id`, u.WorkspaceID, u.Role == "admin", u.ID, string(capability))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []int64{}
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func mergeAccountIDs(sets ...[]int64) []int64 {
	unique := map[int64]struct{}{}
	for _, set := range sets {
		for _, id := range set {
			unique[id] = struct{}{}
		}
	}
	ids := make([]int64, 0, len(unique))
	for id := range unique {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func capabilityForMode(mode string) (Capability, error) {
	switch mode {
	case "view":
		return CapabilityAccountView, nil
	case "operate":
		return CapabilityComputeAction, nil
	case "manage":
		return CapabilityAccountManage, nil
	default:
		return "", errors.New("unsupported authorization mode")
	}
}

// CanAccount evaluates explicit account assignments first. An account with no
// assignments continues to use the legacy access-group policy, allowing a
// workspace to migrate account by account without changing existing access.
func (p *PolicyEngine) CanAccount(ctx context.Context, u User, accountID int64, capability Capability) bool {
	var allowed bool
	err := p.DB.QueryRow(ctx, `
SELECT EXISTS(
 SELECT 1 FROM cloud_accounts a
 WHERE a.id=$1 AND a.workspace_id=$2 AND (
  $3::boolean
  OR EXISTS(
   SELECT 1
   FROM account_access_assignments aa
   JOIN access_roles ar ON ar.id=aa.role_id AND ar.workspace_id=aa.workspace_id
   LEFT JOIN user_groups ug ON aa.principal_type='team' AND ug.group_id=aa.group_id AND ug.user_id=$4
   WHERE aa.workspace_id=$2 AND aa.cloud_account_id=a.id AND aa.service_key='*'
    AND $5=ANY(ar.permissions)
    AND (
     (aa.principal_type='user' AND aa.user_id=$4)
     OR (aa.principal_type='team' AND ug.user_id IS NOT NULL AND
      CASE ug.role WHEN 'manager' THEN 3 WHEN 'operator' THEN 2 ELSE 1 END >=
      CASE $5 WHEN 'account.manage' THEN 3 WHEN 'compute.operate' THEN 2 ELSE 1 END)
    )
  )
  OR (
   NOT EXISTS(SELECT 1 FROM account_access_assignments existing WHERE existing.workspace_id=$2 AND existing.cloud_account_id=a.id)
   AND EXISTS(
    SELECT 1 FROM user_groups legacy
    JOIN access_groups g ON g.id=legacy.group_id AND g.workspace_id=$2
    WHERE legacy.user_id=$4 AND legacy.group_id=a.group_id AND (
     ($5='account.view' AND g.view_dashboard)
     OR ($5='compute.view' AND g.view_dashboard)
     OR ($5='compute.operate' AND g.view_dashboard AND legacy.role IN ('operator','manager'))
     OR ($5='account.manage' AND g.manage_cloud_accounts AND legacy.role='manager')
    )
   )
  )
 )
)`, accountID, u.WorkspaceID, u.Role == "admin", u.ID, string(capability)).Scan(&allowed)
	return err == nil && allowed
}

func (p *PolicyEngine) CanGroup(ctx context.Context, u User, groupID int64, capability string) bool {
	if u.Role == "admin" {
		var allowed bool
		return p.DB.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM access_groups WHERE id=$1 AND workspace_id=$2)", groupID, u.WorkspaceID).Scan(&allowed) == nil && allowed
	}
	column := "manage_cloud_accounts"
	if capability == "members" {
		column = "manage_group_members"
	}
	var allowed bool
	return p.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_groups ug JOIN access_groups g ON g.id=ug.group_id WHERE ug.user_id=$1 AND g.id=$2 AND g.workspace_id=$3 AND ug.role='manager' AND g.`+column+`)`, u.ID, groupID, u.WorkspaceID).Scan(&allowed) == nil && allowed
}

func (a *App) accountAccess(r *http.Request, id int64, mode string) bool {
	capability, err := capabilityForMode(mode)
	return err == nil && a.Policy.CanAccount(r.Context(), current(r), id, capability)
}

func (a *App) groupAccess(r *http.Request, id int64, capability string) bool {
	return a.Policy.CanGroup(r.Context(), current(r), id, capability)
}
