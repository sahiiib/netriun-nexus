package app

import "testing"

func TestValidateSecurityGroupRule(t *testing.T) {
	valid := securityGroupRuleRequest{Region: "cn-hangzhou", Direction: "ingress", Protocol: "tcp", PortFrom: 22, PortTo: 22, CIDR: "203.0.113.10/32", Policy: "accept", Priority: 1, Description: "SSH from office"}
	rule, message := validateSecurityGroupRule(&valid)
	if message != "" || rule.PortRange != "22/22" || rule.ClientToken == "" {
		t.Fatalf("valid rule rejected: rule=%#v message=%q", rule, message)
	}
	all := securityGroupRuleRequest{Region: "cn-hangzhou", Direction: "egress", Protocol: "all", CIDR: "0.0.0.0/0", Policy: "accept", Priority: 100}
	rule, message = validateSecurityGroupRule(&all)
	if message != "" || rule.PortRange != "-1/-1" {
		t.Fatalf("all-protocol rule rejected: rule=%#v message=%q", rule, message)
	}
	invalid := []securityGroupRuleRequest{
		{Region: "bad region", Direction: "ingress", Protocol: "tcp", PortFrom: 22, PortTo: 22, CIDR: "10.0.0.0/8", Policy: "accept", Priority: 1},
		{Region: "cn-hangzhou", Direction: "sideways", Protocol: "tcp", PortFrom: 22, PortTo: 22, CIDR: "10.0.0.0/8", Policy: "accept", Priority: 1},
		{Region: "cn-hangzhou", Direction: "ingress", Protocol: "tcp", PortFrom: 100, PortTo: 22, CIDR: "10.0.0.0/8", Policy: "accept", Priority: 1},
		{Region: "cn-hangzhou", Direction: "ingress", Protocol: "udp", PortFrom: 53, PortTo: 53, CIDR: "not-a-cidr", Policy: "accept", Priority: 1},
		{Region: "cn-hangzhou", Direction: "ingress", Protocol: "icmp", CIDR: "::/0", Policy: "allow", Priority: 1},
	}
	for index := range invalid {
		if _, message = validateSecurityGroupRule(&invalid[index]); message == "" {
			t.Fatalf("invalid rule %d accepted: %#v", index, invalid[index])
		}
	}
}
