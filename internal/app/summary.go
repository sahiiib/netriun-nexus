package app

import "net/http"

func (a *App) summary(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	accountID, ok := a.optionalAccountID(w, r)
	if !ok {
		return
	}
	var instances, running, accounts, regions int
	err := a.DB.QueryRow(r.Context(), `SELECT count(i.id),count(i.id) FILTER(WHERE i.state='running'),count(DISTINCT a.id),count(DISTINCT i.region) FROM cloud_accounts a LEFT JOIN instances i ON i.account_id=a.id WHERE `+scopeSQL+` AND ($4=0 OR a.id=$4)`, u.Role == "admin", u.ID, u.WorkspaceID, accountID).Scan(&instances, &running, &accounts, &regions)
	if err != nil {
		dbError(w, err)
		return
	}
	write(w, 200, map[string]int{"instances": instances, "running": running, "accounts": accounts, "regions": regions})
}
