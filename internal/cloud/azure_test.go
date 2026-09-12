package cloud

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAzureInventoryDetailsAndActions(t *testing.T) {
	actions := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/virtualMachines"):
			fmt.Fprint(w, `{"value":[{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-one","name":"vm-one","location":"eastus","tags":{"team":"platform"},"properties":{"provisioningState":"Succeeded","hardwareProfile":{"vmSize":"Standard_B2s"},"networkProfile":{"networkInterfaces":[{"id":"/subscriptions/sub/networkInterfaces/nic-one"}]}}}]}`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/instanceView"):
			fmt.Fprint(w, `{"computerName":"vm-one","osName":"Linux","statuses":[{"code":"PowerState/running","displayStatus":"VM running"}]}`)
		case r.Method == http.MethodGet:
			fmt.Fprint(w, `{"id":"vm-one"}`)
		case r.Method == http.MethodPost:
			actions = append(actions, r.URL.Path)
			w.WriteHeader(http.StatusAccepted)
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	defer server.Close()
	client := &AzureClient{subscriptionID: "sub", accessToken: "test-token", baseURL: server.URL, httpClient: server.Client()}
	if err := AzureConnection(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	items, err := AzureInventory(context.Background(), client)
	if err != nil || len(items) != 1 || items[0].Region != "eastus" || items[0].State != "running" {
		t.Fatalf("inventory=%#v err=%v", items, err)
	}
	if _, err = AzureDetails(context.Background(), client, items[0].ID); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"start", "stop", "reboot"} {
		if err = AzureAction(context.Background(), client, items[0].ID, action); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
	}
	if len(actions) != 3 {
		t.Fatalf("actions=%v", actions)
	}
}

func TestAzureRejectsInvalidActionAndContinuationHost(t *testing.T) {
	if err := AzureAction(context.Background(), nil, "/vm", "delete"); err == nil {
		t.Fatal("invalid action accepted")
	}
	client := &AzureClient{baseURL: "https://management.azure.com", httpClient: http.DefaultClient}
	if err := client.request(context.Background(), http.MethodGet, "https://attacker.invalid/next", nil); err == nil {
		t.Fatal("untrusted continuation URL accepted")
	}
}
