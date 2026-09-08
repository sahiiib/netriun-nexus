package app

import (
	"context"
	"encoding/json"
	ecs "github.com/alibabacloud-go/ecs-20140526/v7/client"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/netriun/nexus/internal/cloud"
	"net/http"
	"time"
)

func (a *App) instances(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	limit, offset := pagination(r)
	accountID, ok := a.optionalAccountID(w, r)
	if !ok {
		return
	}
	a.list(w, r, `SELECT row_to_json(t) FROM (SELECT i.*,a.name AS account_name,a.provider,a.group_id FROM instances i JOIN cloud_accounts a ON a.id=i.account_id WHERE `+scopeSQL+` AND ($4=0 OR a.id=$4) AND ($5='' OR i.name ILIKE '%'||$5||'%' OR i.instance_id ILIKE '%'||$5||'%' OR i.public_ip ILIKE '%'||$5||'%' OR a.name ILIKE '%'||$5||'%') AND ($6='' OR i.state=$6) AND ($7='' OR i.region=$7) ORDER BY i.name,i.id LIMIT $8 OFFSET $9) t`, u.Role == "admin", u.ID, u.WorkspaceID, accountID, r.URL.Query().Get("q"), r.URL.Query().Get("state"), r.URL.Query().Get("region"), limit, offset)
}
func (a *App) instanceTarget(r *http.Request, id int64, mode string) (int64, string, string, string, error) {
	var accountID int64
	var iid, region, provider string
	err := a.DB.QueryRow(r.Context(), "SELECT i.account_id,i.instance_id,i.region,a.provider FROM instances i JOIN cloud_accounts a ON a.id=i.account_id WHERE i.id=$1 AND a.workspace_id=$2", id, current(r).WorkspaceID).Scan(&accountID, &iid, &region, &provider)
	if err != nil {
		return 0, "", "", "", err
	}
	if !a.accountAccess(r, accountID, mode) {
		return 0, "", "", "", errForbidden
	}
	return accountID, iid, region, provider, nil
}

type accessError string

func (e accessError) Error() string { return string(e) }

const errForbidden accessError = "Access denied"

func (a *App) credentials(ctx context.Context, workspaceID, accountID int64, provider string) (Credentials, error) {
	var encrypted string
	if err := a.DB.QueryRow(ctx, "SELECT credentials FROM cloud_accounts WHERE id=$1 AND workspace_id=$2 AND provider=$3", accountID, workspaceID, provider).Scan(&encrypted); err != nil {
		return Credentials{}, err
	}
	plain, err := a.Vault.Decrypt(encrypted)
	if err != nil {
		return Credentials{}, err
	}
	var c Credentials
	if err = json.Unmarshal([]byte(plain), &c); err != nil {
		return Credentials{}, err
	}
	return c, nil
}
func (a *App) awsClient(ctx context.Context, workspaceID, accountID int64, region string) (*ec2.Client, error) {
	c, err := a.credentials(ctx, workspaceID, accountID, "aws")
	if err != nil {
		return nil, err
	}
	return cloud.Client(region, c.AccessKey, c.SecretKey, c.SessionToken), nil
}
func (a *App) alibabaClient(ctx context.Context, workspaceID, accountID int64, region string) (*ecs.Client, error) {
	c, err := a.credentials(ctx, workspaceID, accountID, "alibaba")
	if err != nil {
		return nil, err
	}
	return cloud.AlibabaClient(region, c.AccessKey, c.SecretKey, c.SessionToken)
}
func (a *App) instance(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	accountID, iid, region, provider, err := a.instanceTarget(r, id, "view")
	if err == errForbidden {
		problem(w, 403, "Access denied")
		return
	}
	if err != nil {
		dbError(w, err)
		return
	}
	var raw json.RawMessage
	err = a.DB.QueryRow(r.Context(), "SELECT row_to_json(t) FROM (SELECT i.*,a.name AS account_name,a.provider FROM instances i JOIN cloud_accounts a ON a.id=i.account_id WHERE i.id=$1 AND a.workspace_id=$2) t", id, current(r).WorkspaceID).Scan(&raw)
	if err != nil {
		dbError(w, err)
		return
	}
	if r.URL.Query().Get("live") != "true" {
		write(w, 200, map[string]any{"instance": raw})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	var details map[string]any
	if provider == "aws" {
		var c *ec2.Client
		c, err = a.awsClient(ctx, current(r).WorkspaceID, accountID, region)
		if err == nil {
			details, err = cloud.Details(ctx, c, iid)
		}
	} else {
		var c *ecs.Client
		c, err = a.alibabaClient(ctx, current(r).WorkspaceID, accountID, region)
		if err == nil {
			details, err = cloud.AlibabaDetails(ctx, c, region, iid)
		}
	}
	if err != nil {
		a.audit(r, "instance.details_failed", iid, nil)
		problem(w, 502, "Cloud details unavailable; check credentials and permissions")
		return
	}
	write(w, 200, map[string]any{"instance": raw, "live": details})
}
func (a *App) action(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
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
	accountID, iid, region, provider, err := a.instanceTarget(r, id, "operate")
	if err == errForbidden {
		problem(w, 403, "Operator or manager access required")
		return
	}
	if err != nil {
		dbError(w, err)
		return
	}
	// Record intent before the external side effect.
	u := current(r)
	if err = a.record(r.Context(), u.WorkspaceID, u.ID, u.Username, "instance."+in.Action+".requested", iid, nil); err != nil {
		problem(w, 503, "Action was not submitted because audit storage is unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	if provider == "aws" {
		var c *ec2.Client
		c, err = a.awsClient(ctx, u.WorkspaceID, accountID, region)
		if err == nil {
			err = cloud.Action(ctx, c, iid, in.Action)
		}
	} else {
		var c *ecs.Client
		c, err = a.alibabaClient(ctx, u.WorkspaceID, accountID, region)
		if err == nil {
			err = cloud.AlibabaAction(ctx, c, iid, in.Action)
		}
	}
	if err != nil {
		a.audit(r, "instance."+in.Action+".failed", iid, nil)
		problem(w, 502, "Cloud provider rejected the action; check instance state and permissions")
		return
	}
	state := ""
	if in.Action == "start" {
		state = "pending"
		if provider == "alibaba" {
			state = "starting"
		}
	}
	if in.Action == "stop" {
		state = "stopping"
	}
	if state != "" {
		a.DB.Exec(r.Context(), "UPDATE instances SET state=$1 WHERE id=$2", state, id)
	}
	a.audit(r, "instance."+in.Action+".accepted", iid, nil)
	write(w, 202, map[string]string{"status": "accepted", "action": in.Action, "instance_id": iid})
}
