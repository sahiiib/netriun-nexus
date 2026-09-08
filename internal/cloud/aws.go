// Package cloud isolates AWS SDK operations from portal persistence and HTTP.
package cloud

import (
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"time"
)

func Client(region, key, secret, token string) *ec2.Client {
	return ec2.NewFromConfig(aws.Config{Region: region, Credentials: credentials.NewStaticCredentialsProvider(key, secret, token), RetryMaxAttempts: 3})
}
func Regions(ctx context.Context, c *ec2.Client) ([]string, error) {
	out, err := c.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, err
	}
	regions := []string{}
	for _, r := range out.Regions {
		regions = append(regions, aws.ToString(r.RegionName))
	}
	return regions, nil
}

type Instance struct {
	ID, Name, State, Type, PublicIP, PrivateIP string
	Details                                    map[string]any
}

func Inventory(ctx context.Context, c *ec2.Client) ([]Instance, error) {
	result := []Instance{}
	p := ec2.NewDescribeInstancesPaginator(c, &ec2.DescribeInstancesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, reservation := range page.Reservations {
			for _, i := range reservation.Instances {
				tags := map[string]string{}
				for _, t := range i.Tags {
					tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
				}
				groups := []string{}
				for _, g := range i.SecurityGroups {
					groups = append(groups, aws.ToString(g.GroupId))
				}
				var launch any
				if i.LaunchTime != nil {
					launch = i.LaunchTime.UTC().Format(time.RFC3339)
				}
				profile := ""
				if i.IamInstanceProfile != nil {
					profile = aws.ToString(i.IamInstanceProfile.Arn)
				}
				state := "unknown"
				if i.State != nil {
					state = string(i.State.Name)
				}
				result = append(result, Instance{aws.ToString(i.InstanceId), tags["Name"], state, string(i.InstanceType), aws.ToString(i.PublicIpAddress), aws.ToString(i.PrivateIpAddress), map[string]any{"tags": tags, "security_group_ids": groups, "launch_time": launch, "vpc_id": aws.ToString(i.VpcId), "subnet_id": aws.ToString(i.SubnetId), "iam_instance_profile": profile}})
			}
		}
	}
	return result, nil
}
func Action(ctx context.Context, c *ec2.Client, id, action string) error {
	var err error
	switch action {
	case "start":
		_, err = c.StartInstances(ctx, &ec2.StartInstancesInput{InstanceIds: []string{id}})
	case "stop":
		_, err = c.StopInstances(ctx, &ec2.StopInstancesInput{InstanceIds: []string{id}})
	case "reboot":
		_, err = c.RebootInstances(ctx, &ec2.RebootInstancesInput{InstanceIds: []string{id}})
	default:
		return errors.New("invalid instance action")
	}
	return err
}
func Details(ctx context.Context, c *ec2.Client, id string) (map[string]any, error) {
	out, err := c.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{id}})
	if err != nil {
		return nil, err
	}
	groupIDs := []string{}
	for _, r := range out.Reservations {
		for _, i := range r.Instances {
			for _, g := range i.SecurityGroups {
				groupIDs = append(groupIDs, aws.ToString(g.GroupId))
			}
		}
	}
	groups := []types.SecurityGroup{}
	if len(groupIDs) > 0 {
		v, e := c.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{GroupIds: groupIDs})
		if e != nil {
			return nil, e
		}
		groups = v.SecurityGroups
	}
	filter := []types.Filter{{Name: aws.String("attachment.instance-id"), Values: []string{id}}}
	volumes := []types.Volume{}
	vp := ec2.NewDescribeVolumesPaginator(c, &ec2.DescribeVolumesInput{Filters: filter})
	for vp.HasMorePages() {
		v, e := vp.NextPage(ctx)
		if e != nil {
			return nil, e
		}
		volumes = append(volumes, v.Volumes...)
	}
	interfaces := []types.NetworkInterface{}
	np := ec2.NewDescribeNetworkInterfacesPaginator(c, &ec2.DescribeNetworkInterfacesInput{Filters: filter})
	for np.HasMorePages() {
		n, e := np.NextPage(ctx)
		if e != nil {
			return nil, e
		}
		interfaces = append(interfaces, n.NetworkInterfaces...)
	}
	return map[string]any{"security_groups": groups, "volumes": volumes, "network_interfaces": interfaces}, nil
}
