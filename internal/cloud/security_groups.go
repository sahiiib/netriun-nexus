package cloud

import (
	"context"
	"errors"
	"strings"

	ecs "github.com/alibabacloud-go/ecs-20140526/v7/client"
)

type AlibabaSecurityGroupRule struct {
	ID          string `json:"id"`
	Direction   string `json:"direction"`
	Protocol    string `json:"protocol"`
	PortRange   string `json:"port_range"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Policy      string `json:"policy"`
	Priority    string `json:"priority"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
}

type AlibabaSecurityGroup struct {
	ID                      string                     `json:"id"`
	Name                    string                     `json:"name"`
	Description             string                     `json:"description"`
	Region                  string                     `json:"region"`
	VPCID                   string                     `json:"vpc_id"`
	Type                    string                     `json:"type"`
	InstanceCount           int32                      `json:"instance_count"`
	RuleCount               int32                      `json:"rule_count"`
	GroupToGroupRuleCount   int32                      `json:"group_to_group_rule_count"`
	AvailableInstanceAmount int32                      `json:"available_instance_amount"`
	ResourceGroupID         string                     `json:"resource_group_id"`
	ServiceManaged          bool                       `json:"service_managed"`
	CreatedAt               string                     `json:"created_at"`
	Rules                   []AlibabaSecurityGroupRule `json:"rules"`
	RulesAvailable          bool                       `json:"rules_available"`
}

func AlibabaSecurityGroups(ctx context.Context, c *ecs.Client, region string) ([]AlibabaSecurityGroup, error) {
	groups := []AlibabaSecurityGroup{}
	next := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		request := new(ecs.DescribeSecurityGroupsRequest).SetRegionId(region).SetMaxResults(100).SetIsQueryEcsCount(true)
		if next != "" {
			request.SetNextToken(next)
		}
		out, err := c.DescribeSecurityGroupsWithOptions(request, alibabaRuntime())
		if err != nil {
			return nil, err
		}
		if out == nil || out.Body == nil {
			return nil, errors.New("Alibaba ECS returned an empty security group response")
		}
		if out.Body.SecurityGroups != nil {
			for _, item := range out.Body.SecurityGroups.SecurityGroup {
				if item == nil || item.SecurityGroupId == nil {
					continue
				}
				groups = append(groups, AlibabaSecurityGroup{
					ID: value(item.SecurityGroupId), Name: value(item.SecurityGroupName), Description: value(item.Description),
					Region: region, VPCID: value(item.VpcId), Type: value(item.SecurityGroupType),
					InstanceCount: int32Value(item.EcsCount), RuleCount: int32Value(item.RuleCount),
					GroupToGroupRuleCount: int32Value(item.GroupToGroupRuleCount), AvailableInstanceAmount: int32Value(item.AvailableInstanceAmount),
					ResourceGroupID: value(item.ResourceGroupId), ServiceManaged: boolValue(item.ServiceManaged), CreatedAt: value(item.CreationTime),
					Rules: []AlibabaSecurityGroupRule{},
				})
			}
		}
		next = value(out.Body.NextToken)
		if next == "" {
			return groups, nil
		}
	}
}

func AlibabaSecurityGroupRules(ctx context.Context, c *ecs.Client, region, groupID string) ([]AlibabaSecurityGroupRule, error) {
	rules := []AlibabaSecurityGroupRule{}
	next := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		request := new(ecs.DescribeSecurityGroupAttributeRequest).
			SetRegionId(region).SetSecurityGroupId(groupID).SetDirection("all").SetMaxResults(1000)
		if next != "" {
			request.SetNextToken(next)
		}
		out, err := c.DescribeSecurityGroupAttributeWithOptions(request, alibabaRuntime())
		if err != nil {
			return nil, err
		}
		if out == nil || out.Body == nil {
			return nil, errors.New("Alibaba ECS returned an empty security group rule response")
		}
		if out.Body.Permissions != nil {
			for _, item := range out.Body.Permissions.Permission {
				if item == nil {
					continue
				}
				rules = append(rules, AlibabaSecurityGroupRule{
					ID: value(item.SecurityGroupRuleId), Direction: value(item.Direction), Protocol: value(item.IpProtocol),
					PortRange: value(item.PortRange), Source: firstNonEmpty(value(item.SourceCidrIp), value(item.Ipv6SourceCidrIp), value(item.SourceGroupId), value(item.SourcePrefixListId)),
					Destination: firstNonEmpty(value(item.DestCidrIp), value(item.Ipv6DestCidrIp), value(item.DestGroupId), value(item.DestPrefixListId)),
					Policy:      value(item.Policy), Priority: value(item.Priority), Description: value(item.Description), CreatedAt: value(item.CreateTime),
				})
			}
		}
		next = value(out.Body.NextToken)
		if next == "" {
			return rules, nil
		}
	}
}

type AlibabaSecurityGroupRuleInput struct {
	Direction   string
	Protocol    string
	PortRange   string
	CIDR        string
	Policy      string
	Priority    string
	Description string
	ClientToken string
}

func AlibabaAuthorizeSecurityGroupRule(ctx context.Context, c *ecs.Client, region, groupID string, rule AlibabaSecurityGroupRuleInput) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if rule.Direction == "egress" {
		permission := new(ecs.AuthorizeSecurityGroupEgressRequestPermissions).
			SetIpProtocol(rule.Protocol).SetPortRange(rule.PortRange).SetPolicy(rule.Policy).
			SetPriority(rule.Priority)
		if rule.Description != "" {
			permission.SetDescription(rule.Description)
		}
		if strings.Contains(rule.CIDR, ":") {
			permission.SetIpv6DestCidrIp(rule.CIDR)
		} else {
			permission.SetDestCidrIp(rule.CIDR)
		}
		request := new(ecs.AuthorizeSecurityGroupEgressRequest).
			SetRegionId(region).SetSecurityGroupId(groupID).SetPermissions([]*ecs.AuthorizeSecurityGroupEgressRequestPermissions{permission}).SetClientToken(rule.ClientToken)
		_, err := c.AuthorizeSecurityGroupEgressWithOptions(request, alibabaRuntime())
		return err
	}
	permission := new(ecs.AuthorizeSecurityGroupRequestPermissions).
		SetIpProtocol(rule.Protocol).SetPortRange(rule.PortRange).SetPolicy(rule.Policy).
		SetPriority(rule.Priority)
	if rule.Description != "" {
		permission.SetDescription(rule.Description)
	}
	if strings.Contains(rule.CIDR, ":") {
		permission.SetIpv6SourceCidrIp(rule.CIDR)
	} else {
		permission.SetSourceCidrIp(rule.CIDR)
	}
	request := new(ecs.AuthorizeSecurityGroupRequest).
		SetRegionId(region).SetSecurityGroupId(groupID).SetPermissions([]*ecs.AuthorizeSecurityGroupRequestPermissions{permission}).SetClientToken(rule.ClientToken)
	_, err := c.AuthorizeSecurityGroupWithOptions(request, alibabaRuntime())
	return err
}

func AlibabaRevokeSecurityGroupRule(ctx context.Context, c *ecs.Client, region, groupID, ruleID, direction, clientToken string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ruleIDs := []*string{&ruleID}
	if direction == "egress" {
		_, err := c.RevokeSecurityGroupEgressWithOptions(new(ecs.RevokeSecurityGroupEgressRequest).
			SetRegionId(region).SetSecurityGroupId(groupID).SetSecurityGroupRuleId(ruleIDs).SetClientToken(clientToken), alibabaRuntime())
		return err
	}
	_, err := c.RevokeSecurityGroupWithOptions(new(ecs.RevokeSecurityGroupRequest).
		SetRegionId(region).SetSecurityGroupId(groupID).SetSecurityGroupRuleId(ruleIDs).SetClientToken(clientToken), alibabaRuntime())
	return err
}

func int32Value(value *int32) int32 {
	if value == nil {
		return 0
	}
	return *value
}

func boolValue(value *bool) bool {
	return value != nil && *value
}

func firstNonEmpty(values ...string) string {
	for _, item := range values {
		if item != "" {
			return item
		}
	}
	return ""
}
