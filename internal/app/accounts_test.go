package app

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
)

func TestValidateProviderCredentials(t *testing.T) {
	validUUID := "11111111-1111-4111-8111-111111111111"
	azure := &Credentials{TenantID: validUUID, ClientID: validUUID, SubscriptionID: validUUID, ClientSecret: "secret"}
	if message := validateCredentials("azure", azure); message != "" {
		t.Fatalf("valid Azure credentials rejected: %s", message)
	}
	if message := validateCredentials("azure", &Credentials{TenantID: "invalid"}); message == "" {
		t.Fatal("invalid Azure credentials accepted")
	}

	keyJSON := validGCPServiceAccountJSON(t)
	gcp := &Credentials{ProjectID: "example-project", ServiceAccountJSON: keyJSON}
	if message := validateCredentials("gcp", gcp); message != "" {
		t.Fatalf("valid GCP credentials rejected: %s", message)
	}
	if message := validateCredentials("gcp", &Credentials{ProjectID: "example-project", ServiceAccountJSON: `{}`}); message == "" {
		t.Fatal("invalid GCP credentials accepted")
	}
}

func validGCPServiceAccountJSON(t *testing.T) string {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyJSON, err := json.Marshal(map[string]string{
		"type":         "service_account",
		"client_email": "nexus@example-project.iam.gserviceaccount.com",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"token_uri":    "https://oauth2.googleapis.com/token",
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(keyJSON)
}
