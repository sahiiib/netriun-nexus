package cloud

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInventoryPaginationAndActions(t *testing.T) {
	pages, actions := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		w.Header().Set("Content-Type", "text/xml")
		switch r.Form.Get("Action") {
		case "DescribeInstances":
			pages++
			if pages == 1 {
				w.Write([]byte(`<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><reservationSet><item><instancesSet><item><instanceId>i-first</instanceId><instanceType>t3.micro</instanceType><instanceState><name>running</name></instanceState><tagSet><item><key>Name</key><value>Production</value></item></tagSet></item></instancesSet></item></reservationSet><nextToken>page-two</nextToken></DescribeInstancesResponse>`))
			} else {
				if r.Form.Get("NextToken") != "page-two" {
					t.Error("pagination token missing")
				}
				w.Write([]byte(`<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><reservationSet><item><instancesSet><item><instanceId>i-second</instanceId><instanceType>t3.small</instanceType><instanceState><name>stopped</name></instanceState></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`))
			}
		case "StartInstances", "StopInstances", "RebootInstances":
			actions++
			if r.Form.Get("InstanceId.1") != "i-first" {
				t.Error("wrong instance target")
			}
			w.Write([]byte(`<` + r.Form.Get("Action") + `Response xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"></` + r.Form.Get("Action") + `Response>`))
		default:
			t.Errorf("unexpected action %s", r.Form.Get("Action"))
			w.WriteHeader(400)
		}
	}))
	defer server.Close()
	c := ec2.NewFromConfig(aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("test", "test", "")}, func(o *ec2.Options) { o.BaseEndpoint = aws.String(server.URL) })
	items, err := Inventory(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if pages != 2 || len(items) != 2 || items[0].Name != "Production" || items[1].State != "stopped" {
		t.Fatalf("unexpected inventory: %+v", items)
	}
	for _, action := range []string{"start", "stop", "reboot"} {
		if err = Action(context.Background(), c, "i-first", action); err != nil {
			t.Fatal(err)
		}
	}
	if err = Action(context.Background(), c, "i-first", "terminate"); err == nil {
		t.Fatal("unsupported action accepted")
	}
	if actions != 3 {
		t.Fatal("invalid action reached AWS")
	}
}
