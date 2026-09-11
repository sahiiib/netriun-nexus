package cloud

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestGCPInventoryDetailsAndActions(t *testing.T) {
	actions := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/aggregated/instances"):
			fmt.Fprint(w, `{"items":{"zones/europe-west1-b":{"instances":[{"id":"42","name":"vm-one","zone":"zones/europe-west1-b","status":"RUNNING","machineType":"machineTypes/e2-small","networkInterfaces":[{"networkIP":"10.0.0.2","accessConfigs":[{"natIP":"203.0.113.2"}]}]}]}}}`)
		case r.Method == http.MethodGet:
			fmt.Fprint(w, `{"id":"42","name":"vm-one"}`)
		case r.Method == http.MethodPost:
			actions = append(actions, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	defer server.Close()
	client := &GCPClient{projectID: "project-one", baseURL: server.URL, tokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}), httpClient: server.Client()}
	items, err := GCPInventory(context.Background(), client)
	if err != nil || len(items) != 1 || items[0].Region != "europe-west1" || items[0].State != "running" {
		t.Fatalf("inventory=%#v err=%v", items, err)
	}
	if _, err = GCPDetails(context.Background(), client, items[0].ID); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"start", "stop", "reboot"} {
		if err = GCPAction(context.Background(), client, items[0].ID, action); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
	}
	if len(actions) != 3 {
		t.Fatalf("actions=%v", actions)
	}
}

func TestGCPRejectsInvalidTargetAndContinuationHost(t *testing.T) {
	if err := GCPAction(context.Background(), nil, "bad-target", "start"); err == nil {
		t.Fatal("invalid target accepted")
	}
	client := &GCPClient{baseURL: "https://compute.googleapis.com", tokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test"}), httpClient: http.DefaultClient}
	if err := client.request(context.Background(), http.MethodGet, "https://attacker.invalid/next", nil); err == nil {
		t.Fatal("untrusted continuation URL accepted")
	}
}
