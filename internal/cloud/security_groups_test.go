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

func TestAlibabaSecurityGroupsRulesAndMutations(t *testing.T) {
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
		case "DescribeSecurityGroups":
			fmt.Fprint(w, `{"RequestId":"groups","SecurityGroups":{"SecurityGroup":[{"SecurityGroupId":"sg-one","SecurityGroupName":"web-tier","Description":"Public web access","VpcId":"vpc-one","SecurityGroupType":"normal","EcsCount":2,"RuleCount":1,"CreationTime":"2026-01-01T00:00Z"}]}}`)
		case "DescribeSecurityGroupAttribute":
			fmt.Fprint(w, `{"RequestId":"rules","Permissions":{"Permission":[{"SecurityGroupRuleId":"sgr-one","Direction":"ingress","IpProtocol":"tcp","PortRange":"443/443","SourceCidrIp":"203.0.113.0/24","Policy":"accept","Priority":"1","Description":"HTTPS"}]}}`)
		case "AuthorizeSecurityGroup", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroup", "RevokeSecurityGroupEgress":
			fmt.Fprint(w, `{"RequestId":"ok"}`)
		default:
			http.Error(w, "unexpected action", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := newAlibabaClient("cn-hangzhou", "test-key", "test-secret", "", endpoint.Host, "HTTP")
	if err != nil {
		t.Fatal(err)
	}
	groups, err := AlibabaSecurityGroups(context.Background(), client, "cn-hangzhou")
	if err != nil || len(groups) != 1 || groups[0].ID != "sg-one" || groups[0].InstanceCount != 2 {
		t.Fatalf("groups = %#v, err = %v", groups, err)
	}
	rules, err := AlibabaSecurityGroupRules(context.Background(), client, "cn-hangzhou", "sg-one")
	if err != nil || len(rules) != 1 || rules[0].ID != "sgr-one" || rules[0].Source != "203.0.113.0/24" {
		t.Fatalf("rules = %#v, err = %v", rules, err)
	}
	base := AlibabaSecurityGroupRuleInput{Protocol: "tcp", PortRange: "443/443", CIDR: "203.0.113.0/24", Policy: "accept", Priority: "1", Description: "HTTPS", ClientToken: "token"}
	for _, direction := range []string{"ingress", "egress"} {
		base.Direction = direction
		if err = AlibabaAuthorizeSecurityGroupRule(context.Background(), client, "cn-hangzhou", "sg-one", base); err != nil {
			t.Fatalf("authorize %s: %v", direction, err)
		}
		if err = AlibabaRevokeSecurityGroupRule(context.Background(), client, "cn-hangzhou", "sg-one", "sgr-one", direction, "token"); err != nil {
			t.Fatalf("revoke %s: %v", direction, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, want := range []string{"DescribeSecurityGroups", "DescribeSecurityGroupAttribute", "AuthorizeSecurityGroup", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroup", "RevokeSecurityGroupEgress"} {
		found := false
		for _, got := range actions {
			found = found || got == want
		}
		if !found {
			t.Errorf("action %s not called; got %v", want, actions)
		}
	}
}
