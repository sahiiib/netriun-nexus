package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const azureComputeAPIVersion = "2024-07-01"

type AzureClient struct {
	subscriptionID string
	accessToken    string
	baseURL        string
	httpClient     *http.Client
}

type azureVM struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Zones      []string          `json:"zones"`
	Properties struct {
		ProvisioningState string `json:"provisioningState"`
		HardwareProfile   struct {
			VMSize string `json:"vmSize"`
		} `json:"hardwareProfile"`
		StorageProfile any `json:"storageProfile"`
		NetworkProfile struct {
			NetworkInterfaces []struct {
				ID string `json:"id"`
			} `json:"networkInterfaces"`
		} `json:"networkProfile"`
	} `json:"properties"`
}

type azureInstanceView struct {
	ComputerName string `json:"computerName"`
	OSName       string `json:"osName"`
	OSVersion    string `json:"osVersion"`
	Statuses     []struct {
		Code          string `json:"code"`
		DisplayStatus string `json:"displayStatus"`
	} `json:"statuses"`
}

func NewAzureClient(ctx context.Context, tenantID, clientID, clientSecret, subscriptionID string) (*AzureClient, error) {
	tokenURL := "https://login.microsoftonline.com/" + url.PathEscape(tenantID) + "/oauth2/v2.0/token"
	form := url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"grant_type":    {"client_credentials"},
		"scope":         {"https://management.azure.com/.default"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 30 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return nil, fmt.Errorf("Azure authentication failed with status %d", response.StatusCode)
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&token); err != nil || token.AccessToken == "" {
		return nil, errors.New("Azure authentication returned an invalid response")
	}
	return &AzureClient{subscriptionID: subscriptionID, accessToken: token.AccessToken, baseURL: "https://management.azure.com", httpClient: client}, nil
}

func (c *AzureClient) request(ctx context.Context, method, target string, out any) error {
	if !strings.HasPrefix(target, "http") {
		target = strings.TrimRight(c.baseURL, "/") + target
	}
	base, baseErr := url.Parse(c.baseURL)
	parsed, targetErr := url.Parse(target)
	if baseErr != nil || targetErr != nil || !strings.EqualFold(base.Host, parsed.Host) || parsed.Scheme != base.Scheme {
		return errors.New("Azure returned an invalid continuation URL")
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(nil))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return fmt.Errorf("Azure request failed with status %d", response.StatusCode)
	}
	if out == nil || response.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(out)
}

func AzureInventory(ctx context.Context, c *AzureClient) ([]Instance, error) {
	target := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Compute/virtualMachines?api-version=%s", url.PathEscape(c.subscriptionID), azureComputeAPIVersion)
	result := []Instance{}
	for target != "" {
		var page struct {
			Value    []azureVM `json:"value"`
			NextLink string    `json:"nextLink"`
		}
		if err := c.request(ctx, http.MethodGet, target, &page); err != nil {
			return nil, err
		}
		for _, vm := range page.Value {
			if vm.ID == "" || vm.Name == "" || vm.Location == "" {
				continue
			}
			var view azureInstanceView
			if err := c.request(ctx, http.MethodGet, vm.ID+"/instanceView?api-version="+azureComputeAPIVersion, &view); err != nil {
				return nil, fmt.Errorf("instance view for %s: %w", vm.Name, err)
			}
			networkInterfaces := make([]string, 0, len(vm.Properties.NetworkProfile.NetworkInterfaces))
			for _, nic := range vm.Properties.NetworkProfile.NetworkInterfaces {
				networkInterfaces = append(networkInterfaces, nic.ID)
			}
			result = append(result, Instance{
				ID: vm.ID, Name: vm.Name, State: azurePowerState(view.Statuses), Type: vm.Properties.HardwareProfile.VMSize, Region: strings.ToLower(vm.Location),
				Details: map[string]any{"provider": "azure", "tags": vm.Tags, "zones": vm.Zones, "resource_group": azureResourceGroup(vm.ID), "network_interface_ids": networkInterfaces, "provisioning_state": vm.Properties.ProvisioningState, "computer_name": view.ComputerName, "os_name": view.OSName, "os_version": view.OSVersion},
			})
		}
		target = page.NextLink
	}
	return result, nil
}

func azurePowerState(statuses []struct {
	Code          string `json:"code"`
	DisplayStatus string `json:"displayStatus"`
}) string {
	for _, status := range statuses {
		if strings.HasPrefix(strings.ToLower(status.Code), "powerstate/") {
			state := strings.TrimPrefix(strings.ToLower(status.Code), "powerstate/")
			switch state {
			case "deallocated", "stopped":
				return "stopped"
			case "deallocating", "stopping":
				return "stopping"
			case "starting":
				return "pending"
			default:
				return state
			}
		}
	}
	return "unknown"
}

func azureResourceGroup(id string) string {
	parts := strings.Split(strings.Trim(id, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourceGroups") {
			return parts[i+1]
		}
	}
	return ""
}

func AzureDetails(ctx context.Context, c *AzureClient, id string) (map[string]any, error) {
	var model map[string]any
	if err := c.request(ctx, http.MethodGet, id+"?api-version="+azureComputeAPIVersion, &model); err != nil {
		return nil, err
	}
	var view map[string]any
	if err := c.request(ctx, http.MethodGet, id+"/instanceView?api-version="+azureComputeAPIVersion, &view); err != nil {
		return nil, err
	}
	return map[string]any{"model": model, "instance_view": view}, nil
}

func AzureAction(ctx context.Context, c *AzureClient, id, action string) error {
	operation := map[string]string{"start": "start", "stop": "deallocate", "reboot": "restart"}[action]
	if operation == "" {
		return errors.New("invalid instance action")
	}
	return c.request(ctx, http.MethodPost, id+"/"+operation+"?api-version="+azureComputeAPIVersion, nil)
}
