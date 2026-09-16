package app

import "testing"

func TestOSSBucketNameValidation(t *testing.T) {
	for _, value := range []string{"nexus-assets", "abc", "bucket-123"} {
		if !ossBucketNamePattern.MatchString(value) {
			t.Fatalf("valid OSS bucket name %q rejected", value)
		}
	}
	for _, value := range []string{"ab", "Uppercase", "-leading", "trailing-", "contains.dot"} {
		if ossBucketNamePattern.MatchString(value) {
			t.Fatalf("invalid OSS bucket name %q accepted", value)
		}
	}
}
