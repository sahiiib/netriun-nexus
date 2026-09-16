package cloud

import (
	"context"
	"strings"
	"time"

	oss "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"
)

type OSSBucket struct {
	Name                   string     `json:"name"`
	Region                 string     `json:"region"`
	Location               string     `json:"location"`
	CreationDate           *time.Time `json:"creation_date,omitempty"`
	StorageClass           string     `json:"storage_class"`
	RedundancyType         string     `json:"redundancy_type"`
	ACL                    string     `json:"acl"`
	Versioning             string     `json:"versioning"`
	Encryption             string     `json:"encryption"`
	ResourceGroupID        string     `json:"resource_group_id"`
	ExtranetEndpoint       string     `json:"extranet_endpoint"`
	IntranetEndpoint       string     `json:"intranet_endpoint"`
	CrossRegionReplication string     `json:"cross_region_replication"`
	TransferAcceleration   string     `json:"transfer_acceleration"`
	BlockPublicAccess      *bool      `json:"block_public_access,omitempty"`
	StorageBytes           int64      `json:"storage_bytes"`
	ObjectCount            int64      `json:"object_count"`
	MultipartUploadCount   int64      `json:"multipart_upload_count"`
	StatModifiedAt         *time.Time `json:"stat_modified_at,omitempty"`
	DetailsAvailable       bool       `json:"details_available"`
	StatsAvailable         bool       `json:"stats_available"`
	Status                 string     `json:"status"`
}

type OSSCreateBucketInput struct {
	Name           string
	Region         string
	StorageClass   string
	RedundancyType string
}

func OSSRegion(value string) string {
	value = strings.TrimSpace(value)
	return strings.TrimPrefix(value, "oss-")
}

func OSSClient(region, accessKey, secretKey, sessionToken string) *oss.Client {
	provider := credentials.NewStaticCredentialsProvider(accessKey, secretKey, sessionToken)
	cfg := oss.LoadDefaultConfig().WithCredentialsProvider(provider).WithRegion(OSSRegion(region)).WithConnectTimeout(10 * time.Second).WithReadWriteTimeout(30 * time.Second).WithRetryMaxAttempts(3)
	return oss.NewClient(cfg)
}

func OSSListBuckets(ctx context.Context, client *oss.Client) ([]OSSBucket, error) {
	paginator := client.NewListBucketsPaginator(&oss.ListBucketsRequest{})
	items := []OSSBucket{}
	for paginator.HasNext() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, bucket := range page.Buckets {
			region := oss.ToString(bucket.Region)
			if region == "" {
				region = OSSRegion(oss.ToString(bucket.Location))
			}
			items = append(items, OSSBucket{Name: oss.ToString(bucket.Name), Region: OSSRegion(region), Location: oss.ToString(bucket.Location), CreationDate: bucket.CreationDate, StorageClass: oss.ToString(bucket.StorageClass), ResourceGroupID: oss.ToString(bucket.ResourceGroupId), ExtranetEndpoint: oss.ToString(bucket.ExtranetEndpoint), IntranetEndpoint: oss.ToString(bucket.IntranetEndpoint), Status: "partial"})
		}
	}
	return items, nil
}

func OSSBucketDetails(ctx context.Context, client *oss.Client, bucket *OSSBucket) error {
	info, err := client.GetBucketInfo(ctx, &oss.GetBucketInfoRequest{Bucket: oss.Ptr(bucket.Name)})
	if err != nil {
		return err
	}
	value := info.BucketInfo
	bucket.DetailsAvailable = true
	bucket.Location = oss.ToString(value.Location)
	bucket.Region = OSSRegion(bucket.Location)
	if bucket.Region == "" {
		bucket.Region = OSSRegion(oss.ToString(value.Location))
	}
	bucket.CreationDate = value.CreationDate
	bucket.StorageClass = oss.ToString(value.StorageClass)
	bucket.RedundancyType = oss.ToString(value.DataRedundancyType)
	bucket.ACL = oss.ToString(value.ACL)
	bucket.Versioning = oss.ToString(value.Versioning)
	bucket.ResourceGroupID = oss.ToString(value.ResourceGroupId)
	bucket.ExtranetEndpoint = oss.ToString(value.ExtranetEndpoint)
	bucket.IntranetEndpoint = oss.ToString(value.IntranetEndpoint)
	bucket.CrossRegionReplication = oss.ToString(value.CrossRegionReplication)
	bucket.TransferAcceleration = oss.ToString(value.TransferAcceleration)
	bucket.BlockPublicAccess = value.BlockPublicAccess
	bucket.Encryption = oss.ToString(value.SseRule.SSEAlgorithm)
	return nil
}

func OSSBucketStats(ctx context.Context, client *oss.Client, bucket *OSSBucket) error {
	stat, err := client.GetBucketStat(ctx, &oss.GetBucketStatRequest{Bucket: oss.Ptr(bucket.Name)})
	if err != nil {
		return err
	}
	bucket.StatsAvailable = true
	bucket.StorageBytes = stat.Storage
	bucket.ObjectCount = stat.ObjectCount
	bucket.MultipartUploadCount = stat.MultipartUploadCount
	if stat.LastModifiedTime > 0 {
		value := time.Unix(stat.LastModifiedTime, 0).UTC()
		bucket.StatModifiedAt = &value
	}
	return nil
}

func OSSCreateBucket(ctx context.Context, client *oss.Client, input OSSCreateBucketInput) error {
	_, err := client.PutBucket(ctx, &oss.PutBucketRequest{
		Bucket: oss.Ptr(input.Name),
		Acl:    oss.BucketACLPrivate,
		CreateBucketConfiguration: &oss.CreateBucketConfiguration{
			StorageClass:       oss.StorageClassType(input.StorageClass),
			DataRedundancyType: oss.DataRedundancyType(input.RedundancyType),
		},
	})
	return err
}
