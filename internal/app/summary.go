package app

import "net/http"

func (a *App) summary(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	ids, err := a.Policy.AccessibleAccountIDs(r.Context(), u, CapabilityAccountView)
	if err != nil {
		dbError(w, err)
		return
	}
	ids, ok := a.requestedAccountIDs(w, r, ids)
	if !ok {
		return
	}
	var instances, running, accounts, regions int
	err = a.DB.QueryRow(r.Context(), `SELECT count(i.id),count(i.id) FILTER(WHERE i.state='running'),count(DISTINCT a.id),count(DISTINCT i.region) FROM cloud_accounts a LEFT JOIN instances i ON i.account_id=a.id WHERE a.workspace_id=$1 AND a.id=ANY($2)`, u.WorkspaceID, ids).Scan(&instances, &running, &accounts, &regions)
	if err != nil {
		dbError(w, err)
		return
	}
	write(w, 200, map[string]int{"instances": instances, "running": running, "accounts": accounts, "regions": regions})
}
