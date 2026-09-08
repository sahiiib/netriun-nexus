package cloud

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

func TestAlibabaRegionsInventoryAndActions(t *testing.T) {
	var mu sync.Mutex
	actions := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.URL.Query().Get("Action")
		if action == "" {
			action = r.Header.Get("x-acs-action")
		}
		mu.Lock()
		actions = append(actions, action)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch action {
		case "DescribeRegions":
			fmt.Fprint(w, `{"RequestId":"r1","Regions":{"Region":[{"RegionId":"cn-hangzhou"},{"RegionId":"ap-southeast-1"}]}}`)
		case "DescribeInstances":
			if r.URL.Query().Get("NextToken") == "next-page" {
				fmt.Fprint(w, `{"RequestId":"r3","Instances":{"Instance":[{"InstanceId":"i-second","InstanceName":"db","Status":"Stopped","InstanceType":"ecs.c7.large","VpcAttributes":{"PrivateIpAddress":{"IpAddress":["10.0.0.3"]}}}]}}`)
				return
			}
			fmt.Fprint(w, `{"RequestId":"r2","NextToken":"next-page","Instances":{"Instance":[{"InstanceId":"i-first","InstanceName":"web","Status":"Running","InstanceType":"ecs.g7.large","CreationTime":"2026-01-01T00:00Z","ZoneId":"cn-hangzhou-h","PublicIpAddress":{"IpAddress":["203.0.113.10"]},"VpcAttributes":{"VpcId":"vpc-one","VSwitchId":"vsw-one","PrivateIpAddress":{"IpAddress":["10.0.0.2"]}},"SecurityGroupIds":{"SecurityGroupId":["sg-one"]},"Tags":{"Tag":[{"TagKey":"env","TagValue":"production"}]}}]}}`)
		case "StartInstance", "StopInstance", "RebootInstance":
			fmt.Fprint(w, `{"RequestId":"action-ok"}`)
		default:
			http.Error(w, "unexpected action", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := newAlibabaClient("cn-hangzhou", "test-key", "test-secret", "", u.Host, "HTTP")
	if err != nil {
		t.Fatal(err)
	}
	regions, err := AlibabaRegions(context.Background(), client)
	if err != nil || len(regions) != 2 || regions[1] != "ap-southeast-1" {
		t.Fatalf("regions = %v, err = %v", regions, err)
	}
	instances, err := AlibabaInventory(context.Background(), client, "cn-hangzhou")
	if err != nil {
		t.Fatal(err)
	}
	if len(instances) != 2 || instances[0].ID != "i-first" || instances[0].State != "running" || instances[0].PublicIP != "203.0.113.10" || instances[0].PrivateIP != "10.0.0.2" {
		t.Fatalf("unexpected instances: %#v", instances)
	}
	for _, action := range []string{"start", "stop", "reboot"} {
		if err = AlibabaAction(context.Background(), client, "i-first", action); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, want := range []string{"DescribeRegions", "DescribeInstances", "StartInstance", "StopInstance", "RebootInstance"} {
		found := false
		for _, got := range actions {
			found = found || got == want
		}
		if !found {
			t.Errorf("action %s not called; got %v", want, actions)
		}
	}
}

func TestAlibabaRejectsInvalidActionAndCancelledContext(t *testing.T) {
	if err := AlibabaAction(context.Background(), nil, "i-one", "delete"); err == nil {
		t.Fatal("invalid action accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := AlibabaRegions(ctx, nil); err == nil {
		t.Fatal("cancelled context accepted")
	}
}
