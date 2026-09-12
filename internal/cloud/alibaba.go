package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	ecs "github.com/alibabacloud-go/ecs-20140526/v7/client"
	"github.com/alibabacloud-go/tea/dara"
)

// AlibabaClient uses the supported Alibaba Cloud V2 SDK and static RAM/STS
// credentials. Callers keep credentials encrypted and only pass plaintext here
// for the lifetime of an API request.
func AlibabaClient(region, key, secret, token string) (*ecs.Client, error) {
	return newAlibabaClient(region, key, secret, token, "", "HTTPS")
}

func newAlibabaClient(region, key, secret, token, endpoint, protocol string) (*ecs.Client, error) {
	config := new(openapi.Config).
		SetRegionId(region).
		SetAccessKeyId(key).
		SetAccessKeySecret(secret).
		SetProtocol(protocol)
	if token != "" {
		config.SetSecurityToken(token)
	}
	if endpoint != "" {
		config.SetEndpoint(endpoint)
	}
	return ecs.NewClient(config)
}

func alibabaRuntime() *dara.RuntimeOptions {
	timeout, attempts := 20_000, 3
	return &dara.RuntimeOptions{ReadTimeout: &timeout, ConnectTimeout: &timeout, Autoretry: dara.Bool(true), MaxAttempts: &attempts}
}

func AlibabaRegions(ctx context.Context, c *ecs.Client) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out, err := c.DescribeRegionsWithOptions(new(ecs.DescribeRegionsRequest).SetAcceptLanguage("en-US").SetResourceType("instance"), alibabaRuntime())
	if err != nil {
		return nil, err
	}
	regions := []string{}
	if out != nil && out.Body != nil && out.Body.Regions != nil {
		for _, region := range out.Body.Regions.Region {
			if region != nil && region.RegionId != nil && *region.RegionId != "" {
				regions = append(regions, *region.RegionId)
			}
		}
	}
	return regions, nil
}

// AlibabaConnection performs a bounded ECS inventory read in the selected
// region so a successful test covers more than AccessKey authentication.
func AlibabaConnection(ctx context.Context, c *ecs.Client, region string) error {
	_, err := c.DescribeInstances(new(ecs.DescribeInstancesRequest).SetRegionId(region).SetMaxResults(1))
	return err
}

func AlibabaInventory(ctx context.Context, c *ecs.Client, region string) ([]Instance, error) {
	result := []Instance{}
	next := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		request := new(ecs.DescribeInstancesRequest).SetRegionId(region).SetMaxResults(100)
		if next != "" {
			request.SetNextToken(next)
		}
		out, err := c.DescribeInstancesWithOptions(request, alibabaRuntime())
		if err != nil {
			return nil, err
		}
		if out == nil || out.Body == nil {
			return nil, errors.New("Alibaba Cloud returned an empty response")
		}
		if out.Body.Instances != nil {
			for _, item := range out.Body.Instances.Instance {
				if item == nil || item.InstanceId == nil {
					continue
				}
				tags := map[string]string{}
				if item.Tags != nil {
					for _, tag := range item.Tags.Tag {
						if tag != nil {
							tags[value(tag.TagKey)] = value(tag.TagValue)
						}
					}
				}
				groups := []string{}
				if item.SecurityGroupIds != nil {
					groups = values(item.SecurityGroupIds.SecurityGroupId)
				}
				publicIP := first(nil)
				if item.PublicIpAddress != nil {
					publicIP = first(item.PublicIpAddress.IpAddress)
				}
				if publicIP == "" && item.EipAddress != nil {
					publicIP = value(item.EipAddress.IpAddress)
				}
				privateIP, vpcID, switchID := "", "", ""
				if item.VpcAttributes != nil {
					vpcID, switchID = value(item.VpcAttributes.VpcId), value(item.VpcAttributes.VSwitchId)
					if item.VpcAttributes.PrivateIpAddress != nil {
						privateIP = first(item.VpcAttributes.PrivateIpAddress.IpAddress)
					}
				}
				if privateIP == "" && item.InnerIpAddress != nil {
					privateIP = first(item.InnerIpAddress.IpAddress)
				}
				result = append(result, Instance{
					ID:        value(item.InstanceId),
					Name:      value(item.InstanceName),
					State:     strings.ToLower(value(item.Status)),
					Type:      value(item.InstanceType),
					PublicIP:  publicIP,
					PrivateIP: privateIP,
					Details: map[string]any{
						"provider": "alibaba", "tags": tags, "security_group_ids": groups,
						"launch_time": value(item.CreationTime), "vpc_id": vpcID, "subnet_id": switchID,
						"zone_id": value(item.ZoneId), "image_id": value(item.ImageId),
						"os_name": value(item.OSNameEn), "charge_type": value(item.InstanceChargeType),
					},
				})
			}
		}
		next = value(out.Body.NextToken)
		if next == "" {
			break
		}
	}
	return result, nil
}

func AlibabaAction(ctx context.Context, c *ecs.Client, id, action string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var err error
	switch action {
	case "start":
		_, err = c.StartInstanceWithOptions(new(ecs.StartInstanceRequest).SetInstanceId(id), alibabaRuntime())
	case "stop":
		_, err = c.StopInstanceWithOptions(new(ecs.StopInstanceRequest).SetInstanceId(id), alibabaRuntime())
	case "reboot":
		_, err = c.RebootInstanceWithOptions(new(ecs.RebootInstanceRequest).SetInstanceId(id), alibabaRuntime())
	default:
		return errors.New("invalid instance action")
	}
	return err
}

// AlibabaDetails returns the provider response for one ECS instance. Keeping
// this provider-native payload makes it possible to expose more ECS fields
// without changing the portal's persistence schema.
func AlibabaDetails(ctx context.Context, c *ecs.Client, region, id string) (map[string]any, error) {
	ids, _ := json.Marshal([]string{id})
	out, err := c.DescribeInstancesWithOptions(new(ecs.DescribeInstancesRequest).
		SetRegionId(region).SetInstanceIds(string(ids)).SetMaxResults(1), alibabaRuntime())
	if err != nil {
		return nil, err
	}
	if out == nil || out.Body == nil || out.Body.Instances == nil || len(out.Body.Instances.Instance) == 0 {
		return nil, errors.New("Alibaba ECS instance not found")
	}
	b, err := json.Marshal(out.Body.Instances.Instance[0])
	if err != nil {
		return nil, err
	}
	var details map[string]any
	if err = json.Unmarshal(b, &details); err != nil {
		return nil, err
	}
	return details, nil
}

func value(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func first(values []*string) string {
	for _, item := range values {
		if item != nil && *item != "" {
			return *item
		}
	}
	return ""
}

func values(items []*string) []string {
	result := make([]string, 0, len(items))
	for _, item := range items {
		if item != nil {
			result = append(result, *item)
		}
	}
	return result
}
