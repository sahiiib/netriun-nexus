package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestEDSInventoryUsersAndMutations(t *testing.T) {
	var mu sync.Mutex
	actions := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("x-acs-action")
		if action == "" {
			action = r.URL.Query().Get("Action")
		}
		mu.Lock()
		actions = append(actions, action)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch action {
		case "DescribeDesktops":
			fmt.Fprint(w, `{"RequestId":"d1","Desktops":[{"DesktopId":"ecd-one","DesktopName":"Engineering","DesktopStatus":"Running","DesktopType":"ecd.basic.large","ChargeType":"PrePaid","EndUserIds":["alice"],"ExpiredTime":"2027-01-01T00:00Z"}]}`)
		case "DescribeRegions":
			fmt.Fprint(w, `{"RequestId":"r1","Regions":[{"RegionId":"cn-hangzhou","LocalName":"China (Hangzhou)"}]}`)
		case "DescribeUsers":
			fmt.Fprint(w, `{"RequestId":"u1","Users":[{"EndUserId":"alice","Email":"alice@example.com","RealNickName":"Alice","Status":0}]}`)
		case "DescribeOfficeSites":
			fmt.Fprint(w, `{"RequestId":"c1","OfficeSites":[{"OfficeSiteId":"dir-one","Name":"Main office"}]}`)
		case "DescribeBundles":
			fmt.Fprint(w, `{"RequestId":"c2","Bundles":[{"BundleId":"bundle-one","BundleName":"General purpose"}]}`)
		case "DescribePolicyGroups":
			fmt.Fprint(w, `{"RequestId":"c3","DescribePolicyGroups":[{"PolicyGroupId":"pg-one","Name":"Default policy"}]}`)
		case "DescribeDesktopTypes":
			fmt.Fprint(w, `{"RequestId":"c4","DesktopTypes":[{"DesktopTypeId":"ecd.basic.large","CpuCount":"4","MemorySize":"8192"}]}`)
		case "DescribeImages":
			fmt.Fprint(w, `{"RequestId":"c5","Images":[{"ImageId":"desktop-image-one","Name":"Windows 11","OsType":"Windows","OsName":"Windows 11"}]}`)
		case "CreateDesktops":
			fmt.Fprint(w, `{"RequestId":"d2","DesktopId":["ecd-two"],"OrderId":"order-one"}`)
		case "RenewDesktops":
			fmt.Fprint(w, `{"RequestId":"d3","OrderId":"order-two"}`)
		case "CreateUsers":
			fmt.Fprint(w, `{"RequestId":"u2","AllSucceed":true,"CreateResult":{"CreatedUsers":[{"EndUserId":"bob","Email":"bob@example.com"}]}}`)
		case "StartDesktops", "StopDesktops", "RebootDesktops", "ModifyUserEntitlement", "SetDesktopMaintenance":
			fmt.Fprint(w, `{"RequestId":"ok"}`)
		case "ModifyDesktopsPolicyGroup":
			fmt.Fprint(w, `{"RequestId":"p1","ModifyResults":[{"DesktopId":"ecd-one","Code":"Success"}]}`)
		case "RunCommand":
			fmt.Fprint(w, `{"RequestId":"cmd1","InvokeId":"invoke-one"}`)
		case "DescribeInvocations":
			fmt.Fprint(w, `{"RequestId":"cmd2","Invocations":[{"InvokeId":"invoke-one","InvocationStatus":"Success","InvokeDesktops":[{"DesktopId":"ecd-one","InvocationStatus":"Success","Output":"hello from desktop","ExitCode":0}]}]}`)
		case "ModifyDesktopChargeType":
			fmt.Fprint(w, `{"RequestId":"b1","DesktopId":["ecd-one"],"OrderId":"order-three"}`)
		default:
			http.Error(w, "unexpected action "+action, http.StatusBadRequest)
		}
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	clients, err := newEDSClients("cn-hangzhou", "test-key", "test-secret", "", u.Host, "HTTP")
	if err != nil {
		t.Fatal(err)
	}
	desktops, err := EDSDesktops(context.Background(), clients.Desktop, "cn-hangzhou")
	if err != nil || len(desktops) != 1 || value(desktops[0].DesktopId) != "ecd-one" || value(desktops[0].RegionId) != "cn-hangzhou" {
		t.Fatalf("desktops = %#v, err = %v", desktops, err)
	}
	encodedDesktop, err := json.Marshal(desktops[0])
	if err != nil || !strings.Contains(string(encodedDesktop), `"DesktopId":"ecd-one"`) || !strings.Contains(string(encodedDesktop), `"RegionId":"cn-hangzhou"`) {
		t.Fatalf("regional desktop JSON = %s, err = %v", encodedDesktop, err)
	}
	regions, err := EDSRegions(context.Background(), clients.Desktop)
	if err != nil || len(regions) != 1 || regions[0].ID != "cn-hangzhou" {
		t.Fatalf("regions = %#v, err = %v", regions, err)
	}
	count, err := EDSDesktopCount(context.Background(), clients.Desktop, "cn-hangzhou")
	if err != nil || count != 1 {
		t.Fatalf("desktop count = %d, err = %v", count, err)
	}
	users, err := EDSUsers(context.Background(), clients.User)
	if err != nil || len(users) != 1 || value(users[0].EndUserId) != "alice" {
		t.Fatalf("users = %#v, err = %v", users, err)
	}
	catalog, err := EDSCatalogForRegion(context.Background(), clients.Desktop, "cn-hangzhou")
	if err != nil || len(catalog.OfficeSites) != 1 || len(catalog.Bundles) != 1 || len(catalog.PolicyGroups) != 1 {
		t.Fatalf("catalog = %#v, err = %v", catalog, err)
	}
	customCatalog, err := EDSCustomCatalogForRegion(context.Background(), clients.Desktop, "cn-hangzhou")
	if err != nil || len(customCatalog.DesktopTypes) != 1 || len(customCatalog.Images) != 1 {
		t.Fatalf("custom catalog = %#v, err = %v", customCatalog, err)
	}
	created, err := EDSCreateDesktop(context.Background(), clients.Desktop, CreateDesktopInput{Region: "cn-hangzhou", OfficeSiteID: "dir-one", BundleID: "bundle-one", PolicyGroupID: "pg-one", Name: "desktop", Amount: 1, ChargeType: "PostPaid"})
	if err != nil || created == nil || len(created.DesktopId) != 1 {
		t.Fatalf("create desktop = %#v, err = %v", created, err)
	}
	if _, err = EDSRenew(context.Background(), clients.Desktop, "cn-hangzhou", "ecd-one", "Month", 1, false); err != nil {
		t.Fatal(err)
	}
	if err = EDSEntitlement(context.Background(), clients.Desktop, "cn-hangzhou", "ecd-one", []string{"alice"}, true); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"start", "stop", "reboot"} {
		if err = EDSDesktopAction(context.Background(), clients.Desktop, "cn-hangzhou", "ecd-one", action); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
	}
	if _, err = EDSChangePolicy(context.Background(), clients.Desktop, "cn-hangzhou", "ecd-one", "pg-one"); err != nil {
		t.Fatal(err)
	}
	if err = EDSMaintenance(context.Background(), clients.Desktop, "cn-hangzhou", "ecd-one", "ENTER"); err != nil {
		t.Fatal(err)
	}
	if _, err = EDSRunCommand(context.Background(), clients.Desktop, "cn-hangzhou", "ecd-one", "Get-Date", "RunPowerShellScript", 300); err != nil {
		t.Fatal(err)
	}
	status, err := EDSDesktopStatus(context.Background(), clients.Desktop, "cn-hangzhou", "ecd-one")
	if err != nil || status != "Running" {
		t.Fatalf("desktop status = %q, err = %v", status, err)
	}
	invocation, err := EDSInvocation(context.Background(), clients.Desktop, "cn-hangzhou", "ecd-one", "invoke-one")
	if err != nil || !invocation.Completed || invocation.Status != "Success" || invocation.Output != "hello from desktop" || invocation.ExitCode == nil || *invocation.ExitCode != 0 {
		t.Fatalf("invocation = %#v, err = %v", invocation, err)
	}
	if _, err = EDSChangeBilling(context.Background(), clients.Desktop, "cn-hangzhou", "ecd-one", "PrePaid", "Month", 1, false); err != nil {
		t.Fatal(err)
	}
	createdUser, err := EDSCreateUser(context.Background(), clients.User, "bob", "bob@example.com", "Bob", "", false)
	if err != nil || createdUser.AllSucceed == nil || !*createdUser.AllSucceed {
		t.Fatalf("create user = %#v, err = %v", createdUser, err)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, want := range []string{"DescribeDesktops", "DescribeRegions", "DescribeUsers", "DescribeOfficeSites", "DescribeBundles", "DescribePolicyGroups", "DescribeDesktopTypes", "DescribeImages", "CreateDesktops", "RenewDesktops", "ModifyUserEntitlement", "StartDesktops", "StopDesktops", "RebootDesktops", "ModifyDesktopsPolicyGroup", "SetDesktopMaintenance", "RunCommand", "DescribeInvocations", "ModifyDesktopChargeType", "CreateUsers"} {
		found := false
		for _, got := range actions {
			found = found || got == want
		}
		if !found {
			t.Errorf("action %s not called; got %v", want, actions)
		}
	}
}

func TestEDSRejectsInvalidActionAndCancelledContext(t *testing.T) {
	if err := EDSDesktopAction(context.Background(), nil, "cn-hangzhou", "ecd-one", "delete"); err == nil {
		t.Fatal("invalid action accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := EDSDesktops(ctx, nil, "cn-hangzhou"); err == nil {
		t.Fatal("cancelled context accepted")
	}
}

func TestEDSUserEndpointRegionRouting(t *testing.T) {
	for _, test := range []struct {
		desktopRegion string
		userRegion    string
	}{
		{"cn-hangzhou", "cn-shanghai"},
		{"cn-hongkong", "ap-southeast-1"},
		{"eu-central-1", "ap-southeast-1"},
	} {
		clients, err := EDSClient(test.desktopRegion, "key", "secret", "")
		if err != nil {
			t.Fatal(err)
		}
		if clients.User.RegionId == nil || *clients.User.RegionId != test.userRegion {
			t.Errorf("desktop region %s routed to user region %v; want %s", test.desktopRegion, clients.User.RegionId, test.userRegion)
		}
	}
}
