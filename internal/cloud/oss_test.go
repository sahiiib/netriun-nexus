package cloud

import "testing"

func TestOSSRegion(t *testing.T) {
	for input, expected := range map[string]string{"oss-cn-hangzhou": "cn-hangzhou", "cn-shanghai": "cn-shanghai", " oss-ap-southeast-1 ": "ap-southeast-1"} {
		if got := OSSRegion(input); got != expected {
			t.Fatalf("OSSRegion(%q)=%q, want %q", input, got, expected)
		}
	}
}
