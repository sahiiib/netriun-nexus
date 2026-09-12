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

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jwt"
)

type GCPClient struct {
	projectID   string
	baseURL     string
	tokenSource oauth2.TokenSource
	httpClient  *http.Client
}

type gcpInstance struct {
	ID                json.Number       `json:"id"`
	Name              string            `json:"name"`
	Zone              string            `json:"zone"`
	Status            string            `json:"status"`
	MachineType       string            `json:"machineType"`
	CreationTimestamp string            `json:"creationTimestamp"`
	Labels            map[string]string `json:"labels"`
	Tags              struct {
		Items []string `json:"items"`
	} `json:"tags"`
	NetworkInterfaces []struct {
		Network       string `json:"network"`
		Subnetwork    string `json:"subnetwork"`
		NetworkIP     string `json:"networkIP"`
		AccessConfigs []struct {
			NatIP string `json:"natIP"`
		} `json:"accessConfigs"`
	} `json:"networkInterfaces"`
}

func NewGCPClient(ctx context.Context, projectID, serviceAccountJSON string) (*GCPClient, error) {
	var key struct {
		ClientEmail  string `json:"client_email"`
		PrivateKey   string `json:"private_key"`
		PrivateKeyID string `json:"private_key_id"`
		TokenURI     string `json:"token_uri"`
	}
	if err := json.Unmarshal([]byte(serviceAccountJSON), &key); err != nil {
		return nil, fmt.Errorf("invalid GCP service account JSON: %w", err)
	}
	if key.ClientEmail == "" || key.PrivateKey == "" {
		return nil, errors.New("invalid GCP service account JSON")
	}
	if key.TokenURI != "https://oauth2.googleapis.com/token" {
		return nil, errors.New("GCP service account token URI is not trusted")
	}
	config := &jwt.Config{Email: key.ClientEmail, PrivateKey: []byte(key.PrivateKey), PrivateKeyID: key.PrivateKeyID, TokenURL: key.TokenURI, Scopes: []string{"https://www.googleapis.com/auth/cloud-platform"}}
	return &GCPClient{
		projectID:   projectID,
		baseURL:     "https://compute.googleapis.com/compute/v1",
		tokenSource: oauth2.ReuseTokenSource(nil, config.TokenSource(ctx)),
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (c *GCPClient) request(ctx context.Context, method, target string, out any) error {
	token, err := c.tokenSource.Token()
	if err != nil {
		return fmt.Errorf("GCP authentication failed: %w", err)
	}
	if !strings.HasPrefix(target, "http") {
		target = strings.TrimRight(c.baseURL, "/") + target
	}
	base, baseErr := url.Parse(c.baseURL)
	parsed, targetErr := url.Parse(target)
	if baseErr != nil || targetErr != nil || !strings.EqualFold(base.Host, parsed.Host) || parsed.Scheme != base.Scheme {
		return errors.New("GCP returned an invalid continuation URL")
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(nil))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return fmt.Errorf("GCP request failed with status %d", response.StatusCode)
	}
	if out == nil || response.StatusCode == http.StatusNoContent {
		io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return nil
	}
	return json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(out)
}

func GCPInventory(ctx context.Context, c *GCPClient) ([]Instance, error) {
	target := fmt.Sprintf("/projects/%s/aggregated/instances?returnPartialSuccess=true&maxResults=500", url.PathEscape(c.projectID))
	result := []Instance{}
	for target != "" {
		var page struct {
			Items map[string]struct {
				Instances []gcpInstance `json:"instances"`
			} `json:"items"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := c.request(ctx, http.MethodGet, target, &page); err != nil {
			return nil, err
		}
		for _, scope := range page.Items {
			for _, vm := range scope.Instances {
				zone := lastResourcePart(vm.Zone)
				if vm.Name == "" || zone == "" {
					continue
				}
				privateIP, publicIP, network, subnet := "", "", "", ""
				if len(vm.NetworkInterfaces) > 0 {
					nic := vm.NetworkInterfaces[0]
					privateIP, network, subnet = nic.NetworkIP, lastResourcePart(nic.Network), lastResourcePart(nic.Subnetwork)
					if len(nic.AccessConfigs) > 0 {
						publicIP = nic.AccessConfigs[0].NatIP
					}
				}
				result = append(result, Instance{
					ID: zone + "/" + vm.Name, Name: vm.Name, State: gcpState(vm.Status), Type: lastResourcePart(vm.MachineType), PublicIP: publicIP, PrivateIP: privateIP, Region: GCPRegion(zone),
					Details: map[string]any{"provider": "gcp", "provider_id": vm.ID.String(), "tags": vm.Labels, "network_tags": vm.Tags.Items, "launch_time": vm.CreationTimestamp, "zone": zone, "network": network, "subnet_id": subnet},
				})
			}
		}
		if page.NextPageToken == "" {
			target = ""
		} else {
			target = fmt.Sprintf("/projects/%s/aggregated/instances?returnPartialSuccess=true&maxResults=500&pageToken=%s", url.PathEscape(c.projectID), url.QueryEscape(page.NextPageToken))
		}
	}
	return result, nil
}

func GCPConnection(ctx context.Context, c *GCPClient) error {
	var page struct {
		Items map[string]json.RawMessage `json:"items"`
	}
	target := fmt.Sprintf("/projects/%s/aggregated/instances?returnPartialSuccess=true&maxResults=1", url.PathEscape(c.projectID))
	return c.request(ctx, http.MethodGet, target, &page)
}

func gcpState(status string) string {
	switch strings.ToUpper(status) {
	case "RUNNING":
		return "running"
	case "TERMINATED", "SUSPENDED":
		return "stopped"
	case "STOPPING", "SUSPENDING":
		return "stopping"
	case "PROVISIONING", "STAGING", "REPAIRING":
		return "pending"
	default:
		return strings.ToLower(status)
	}
}

func gcpTarget(id string) (string, string, error) {
	zone, name, ok := strings.Cut(id, "/")
	if !ok || zone == "" || name == "" || strings.Contains(name, "/") {
		return "", "", errors.New("invalid GCP instance identifier")
	}
	return zone, name, nil
}

func GCPDetails(ctx context.Context, c *GCPClient, id string) (map[string]any, error) {
	zone, name, err := gcpTarget(id)
	if err != nil {
		return nil, err
	}
	var details map[string]any
	target := fmt.Sprintf("/projects/%s/zones/%s/instances/%s", url.PathEscape(c.projectID), url.PathEscape(zone), url.PathEscape(name))
	if err = c.request(ctx, http.MethodGet, target, &details); err != nil {
		return nil, err
	}
	return details, nil
}

func GCPAction(ctx context.Context, c *GCPClient, id, action string) error {
	zone, name, err := gcpTarget(id)
	if err != nil {
		return err
	}
	operation := map[string]string{"start": "start", "stop": "stop", "reboot": "reset"}[action]
	if operation == "" {
		return errors.New("invalid instance action")
	}
	target := fmt.Sprintf("/projects/%s/zones/%s/instances/%s/%s", url.PathEscape(c.projectID), url.PathEscape(zone), url.PathEscape(name), operation)
	return c.request(ctx, http.MethodPost, target, nil)
}

func lastResourcePart(value string) string {
	value = strings.TrimRight(value, "/")
	if index := strings.LastIndexByte(value, '/'); index >= 0 {
		return value[index+1:]
	}
	return value
}

func GCPRegion(zone string) string {
	if index := strings.LastIndexByte(zone, '-'); index > 0 {
		return zone[:index]
	}
	return zone
}
