package cloud

import (
	"context"
	"errors"
	"strings"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	ecd "github.com/alibabacloud-go/ecd-20200930/v5/client"
	edsuser "github.com/alibabacloud-go/eds-user-20210308/v2/client"
)

type EDSClients struct {
	Desktop *ecd.Client
	User    *edsuser.Client
}

type EDSCatalog struct {
	OfficeSites  []*ecd.DescribeOfficeSitesResponseBodyOfficeSites           `json:"office_sites"`
	Bundles      []*ecd.DescribeBundlesResponseBodyBundles                   `json:"bundles"`
	PolicyGroups []*ecd.DescribePolicyGroupsResponseBodyDescribePolicyGroups `json:"policy_groups"`
}

type EDSRegion struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// EDSDesktop keeps the provider payload intact and adds the region that was
// used to retrieve it. Alibaba's DescribeDesktops item does not include that
// information, but cross-region views need it for subsequent operations.
type EDSDesktop struct {
	*ecd.DescribeDesktopsResponseBodyDesktops
	RegionId *string `json:"RegionId,omitempty"`
}

type CreateDesktopInput struct {
	Region, OfficeSiteID, BundleID, PolicyGroupID, Name string
	Amount, Period                                      int32
	ChargeType, PeriodUnit                              string
	EndUserIDs                                          []string
	AutoPay, AutoRenew                                  bool
}

func EDSClient(region, key, secret, token string) (*EDSClients, error) {
	return newEDSClients(region, key, secret, token, "", "HTTPS")
}

func newEDSClients(region, key, secret, token, endpoint, protocol string) (*EDSClients, error) {
	config := func(configRegion string) *openapi.Config {
		value := new(openapi.Config).SetRegionId(configRegion).SetAccessKeyId(key).SetAccessKeySecret(secret).SetProtocol(protocol)
		if token != "" {
			value.SetSecurityToken(token)
		}
		if endpoint != "" {
			value.SetEndpoint(endpoint)
		}
		return value
	}
	desktop, err := ecd.NewClient(config(region))
	if err != nil {
		return nil, err
	}
	// The EDS user-directory API is global within an Alibaba partition. Its
	// official SDK only publishes cn-shanghai (China mainland) and
	// ap-southeast-1 (international) endpoints. Deriving an endpoint from a
	// desktop region such as cn-hongkong produces a non-existent DNS name.
	userRegion := "ap-southeast-1"
	if strings.HasPrefix(region, "cn-") && region != "cn-hongkong" {
		userRegion = "cn-shanghai"
	}
	users, err := edsuser.NewClient(config(userRegion))
	if err != nil {
		return nil, err
	}
	return &EDSClients{Desktop: desktop, User: users}, nil
}

func EDSDesktops(ctx context.Context, c *ecd.Client, region string) ([]*EDSDesktop, error) {
	items := []*EDSDesktop{}
	next := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := new(ecd.DescribeDesktopsRequest).SetRegionId(region).SetMaxResults(100)
		if next != "" {
			req.SetNextToken(next)
		}
		out, err := c.DescribeDesktopsWithOptions(req, alibabaRuntime())
		if err != nil {
			return nil, err
		}
		if out == nil || out.Body == nil {
			return nil, errors.New("Alibaba EDS returned an empty response")
		}
		for _, desktop := range out.Body.Desktops {
			if desktop != nil {
				items = append(items, &EDSDesktop{DescribeDesktopsResponseBodyDesktops: desktop, RegionId: stringPointer(region)})
			}
		}
		next = value(out.Body.NextToken)
		if next == "" {
			return items, nil
		}
	}
}

func EDSDesktopCount(ctx context.Context, c *ecd.Client, region string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	timeout, attempts := 7_000, 1
	runtime := alibabaRuntime()
	runtime.ReadTimeout, runtime.ConnectTimeout, runtime.MaxAttempts = &timeout, &timeout, &attempts
	out, err := c.DescribeDesktopsWithOptions(new(ecd.DescribeDesktopsRequest).SetRegionId(region).SetMaxResults(1), runtime)
	if err != nil {
		return 0, err
	}
	if out == nil || out.Body == nil {
		return 0, errors.New("Alibaba EDS returned an empty desktop-count response")
	}
	if out.Body.TotalCount != nil {
		return int(*out.Body.TotalCount), nil
	}
	return len(out.Body.Desktops), nil
}

func EDSRegions(ctx context.Context, c *ecd.Client) ([]EDSRegion, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out, err := c.DescribeRegionsWithOptions(new(ecd.DescribeRegionsRequest).SetAcceptLanguage("en-US"), alibabaRuntime())
	if err != nil {
		return nil, err
	}
	if out == nil || out.Body == nil {
		return nil, errors.New("Alibaba EDS returned an empty region response")
	}
	items := make([]EDSRegion, 0, len(out.Body.Regions))
	for _, item := range out.Body.Regions {
		if item == nil || value(item.RegionId) == "" {
			continue
		}
		items = append(items, EDSRegion{ID: value(item.RegionId), Name: value(item.LocalName)})
	}
	return items, nil
}

func EDSUsers(ctx context.Context, c *edsuser.Client) ([]*edsuser.DescribeUsersResponseBodyUsers, error) {
	items := []*edsuser.DescribeUsersResponseBodyUsers{}
	next := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := new(edsuser.DescribeUsersRequest).SetMaxResults(100)
		if next != "" {
			req.SetNextToken(next)
		}
		out, err := c.DescribeUsersWithOptions(req, alibabaRuntime())
		if err != nil {
			return nil, err
		}
		if out == nil || out.Body == nil {
			return nil, errors.New("Alibaba EDS User returned an empty response")
		}
		items = append(items, out.Body.Users...)
		next = value(out.Body.NextToken)
		if next == "" {
			return items, nil
		}
	}
}

func EDSCatalogForRegion(ctx context.Context, c *ecd.Client, region string) (EDSCatalog, error) {
	if err := ctx.Err(); err != nil {
		return EDSCatalog{}, err
	}
	result := EDSCatalog{OfficeSites: []*ecd.DescribeOfficeSitesResponseBodyOfficeSites{}, Bundles: []*ecd.DescribeBundlesResponseBodyBundles{}, PolicyGroups: []*ecd.DescribePolicyGroupsResponseBodyDescribePolicyGroups{}}
	for next := ""; ; {
		req := new(ecd.DescribeOfficeSitesRequest).SetRegionId(region).SetMaxResults(100)
		if next != "" {
			req.SetNextToken(next)
		}
		out, err := c.DescribeOfficeSitesWithOptions(req, alibabaRuntime())
		if err != nil {
			return result, err
		}
		if out == nil || out.Body == nil {
			return result, errors.New("Alibaba EDS returned an empty office-site response")
		}
		result.OfficeSites = append(result.OfficeSites, out.Body.OfficeSites...)
		next = value(out.Body.NextToken)
		if next == "" {
			break
		}
	}
	for next := ""; ; {
		req := new(ecd.DescribeBundlesRequest).SetRegionId(region).SetMaxResults(100)
		if next != "" {
			req.SetNextToken(next)
		}
		out, err := c.DescribeBundlesWithOptions(req, alibabaRuntime())
		if err != nil {
			return result, err
		}
		if out == nil || out.Body == nil {
			return result, errors.New("Alibaba EDS returned an empty bundle response")
		}
		result.Bundles = append(result.Bundles, out.Body.Bundles...)
		next = value(out.Body.NextToken)
		if next == "" {
			break
		}
	}
	for next := ""; ; {
		req := new(ecd.DescribePolicyGroupsRequest).SetRegionId(region).SetMaxResults(100)
		if next != "" {
			req.SetNextToken(next)
		}
		out, err := c.DescribePolicyGroupsWithOptions(req, alibabaRuntime())
		if err != nil {
			return result, err
		}
		if out == nil || out.Body == nil {
			return result, errors.New("Alibaba EDS returned an empty policy response")
		}
		result.PolicyGroups = append(result.PolicyGroups, out.Body.DescribePolicyGroups...)
		next = value(out.Body.NextToken)
		if next == "" {
			break
		}
	}
	return result, nil
}

func EDSCreateDesktop(ctx context.Context, c *ecd.Client, in CreateDesktopInput) (*ecd.CreateDesktopsResponseBody, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	req := new(ecd.CreateDesktopsRequest).SetRegionId(in.Region).SetOfficeSiteId(in.OfficeSiteID).SetBundleId(in.BundleID).
		SetPolicyGroupId(in.PolicyGroupID).SetDesktopName(in.Name).SetAmount(in.Amount).SetChargeType(in.ChargeType).
		SetAutoPay(in.AutoPay).SetAutoRenew(in.AutoRenew)
	if in.Period > 0 {
		req.SetPeriod(in.Period).SetPeriodUnit(in.PeriodUnit)
	}
	if len(in.EndUserIDs) > 0 {
		req.SetEndUserId(stringPointers(in.EndUserIDs)).SetUserAssignMode("ALL")
	}
	out, err := c.CreateDesktopsWithOptions(req, alibabaRuntime())
	if err != nil {
		return nil, err
	}
	if out == nil || out.Body == nil {
		return nil, errors.New("Alibaba EDS returned an empty create response")
	}
	return out.Body, nil
}

func EDSRenew(ctx context.Context, c *ecd.Client, region, desktopID, unit string, period int32, autoPay bool) (*ecd.RenewDesktopsResponseBody, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out, err := c.RenewDesktopsWithOptions(new(ecd.RenewDesktopsRequest).SetRegionId(region).SetDesktopId(stringPointers([]string{desktopID})).SetPeriod(period).SetPeriodUnit(unit).SetAutoPay(autoPay), alibabaRuntime())
	if err != nil {
		return nil, err
	}
	if out == nil || out.Body == nil {
		return nil, errors.New("Alibaba EDS returned an empty renewal response")
	}
	return out.Body, nil
}

func EDSEntitlement(ctx context.Context, c *ecd.Client, region, desktopID string, userIDs []string, bind bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	req := new(ecd.ModifyUserEntitlementRequest).SetRegionId(region).SetEndUserId(stringPointers(userIDs))
	if bind {
		req.SetAuthorizeDesktopId(stringPointers([]string{desktopID}))
	} else {
		req.SetRevokeDesktopId(stringPointers([]string{desktopID}))
	}
	_, err := c.ModifyUserEntitlementWithOptions(req, alibabaRuntime())
	return err
}

func EDSDesktopAction(ctx context.Context, c *ecd.Client, region, desktopID, action string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ids := stringPointers([]string{desktopID})
	var err error
	switch action {
	case "start":
		_, err = c.StartDesktopsWithOptions(new(ecd.StartDesktopsRequest).SetRegionId(region).SetDesktopId(ids), alibabaRuntime())
	case "stop":
		_, err = c.StopDesktopsWithOptions(new(ecd.StopDesktopsRequest).SetRegionId(region).SetDesktopId(ids), alibabaRuntime())
	case "reboot":
		_, err = c.RebootDesktopsWithOptions(new(ecd.RebootDesktopsRequest).SetRegionId(region).SetDesktopId(ids), alibabaRuntime())
	default:
		return errors.New("invalid desktop action")
	}
	return err
}

func EDSChangePolicy(ctx context.Context, c *ecd.Client, region, desktopID, policyID string) (*ecd.ModifyDesktopsPolicyGroupResponseBody, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out, err := c.ModifyDesktopsPolicyGroupWithOptions(new(ecd.ModifyDesktopsPolicyGroupRequest).SetRegionId(region).SetDesktopId(stringPointers([]string{desktopID})).SetPolicyGroupId(policyID), alibabaRuntime())
	if err != nil {
		return nil, err
	}
	if out == nil || out.Body == nil {
		return nil, errors.New("Alibaba EDS returned an empty policy-change response")
	}
	return out.Body, nil
}

func EDSMaintenance(ctx context.Context, c *ecd.Client, region, desktopID, mode string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := c.SetDesktopMaintenanceWithOptions(new(ecd.SetDesktopMaintenanceRequest).SetRegionId(region).SetDesktopIds(stringPointers([]string{desktopID})).SetMode(mode), alibabaRuntime())
	return err
}

func EDSRunCommand(ctx context.Context, c *ecd.Client, region, desktopID, command, commandType string, timeout int64) (*ecd.RunCommandResponseBody, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	req := new(ecd.RunCommandRequest).SetRegionId(region).SetDesktopId(stringPointers([]string{desktopID})).SetCommandContent(command).SetContentEncoding("PlainText").SetType(commandType).SetTimeout(timeout)
	out, err := c.RunCommandWithOptions(req, alibabaRuntime())
	if err != nil {
		return nil, err
	}
	if out == nil || out.Body == nil {
		return nil, errors.New("Alibaba EDS returned an empty command response")
	}
	return out.Body, nil
}

func EDSChangeBilling(ctx context.Context, c *ecd.Client, region, desktopID, chargeType, periodUnit string, period int32, autoPay bool) (*ecd.ModifyDesktopChargeTypeResponseBody, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	req := new(ecd.ModifyDesktopChargeTypeRequest).SetRegionId(region).SetDesktopId(stringPointers([]string{desktopID})).SetChargeType(chargeType).SetAutoPay(autoPay)
	if chargeType == "PrePaid" {
		req.SetPeriod(period).SetPeriodUnit(periodUnit)
	}
	out, err := c.ModifyDesktopChargeTypeWithOptions(req, alibabaRuntime())
	if err != nil {
		return nil, err
	}
	if out == nil || out.Body == nil {
		return nil, errors.New("Alibaba EDS returned an empty billing-change response")
	}
	return out.Body, nil
}

func EDSCreateUser(ctx context.Context, c *edsuser.Client, username, email, displayName, password string, localAdmin bool) (*edsuser.CreateUsersResponseBody, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	u := new(edsuser.CreateUsersRequestUsers).SetEndUserId(username).SetEmail(email)
	if displayName != "" {
		u.SetRealNickName(displayName)
	}
	if password != "" {
		u.SetPassword(password)
	}
	out, err := c.CreateUsersWithOptions(new(edsuser.CreateUsersRequest).SetUsers([]*edsuser.CreateUsersRequestUsers{u}).SetIsLocalAdmin(localAdmin), alibabaRuntime())
	if err != nil {
		return nil, err
	}
	if out == nil || out.Body == nil {
		return nil, errors.New("Alibaba EDS User returned an empty create response")
	}
	return out.Body, nil
}

func stringPointers(values []string) []*string {
	items := make([]*string, 0, len(values))
	for _, v := range values {
		value := v
		items = append(items, &value)
	}
	return items
}

func stringPointer(value string) *string {
	return &value
}
