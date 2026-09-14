package app

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestNormalizeOIDCConfig(t *testing.T) {
	cfg := identityProviderConfig{IssuerURL: "https://identity.example.com/", ClientID: "nexus", ClientSecret: "secret"}
	if err := normalizeIdentityProviderConfig("oidc", &cfg, "https://nexus.example.com", "provider"); err != nil {
		t.Fatal(err)
	}
	if cfg.IssuerURL != "https://identity.example.com" || cfg.EmailClaim != "email" || cfg.GroupsClaim != "groups" || len(cfg.Scopes) == 0 || cfg.Scopes[0] != "openid" {
		t.Fatalf("unexpected normalized config: %#v", cfg)
	}
	cfg.IssuerURL = "http://identity.example.com"
	if err := normalizeIdentityProviderConfig("oidc", &cfg, "https://nexus.example.com", "provider"); err == nil {
		t.Fatal("insecure OIDC issuer was accepted")
	}
}

func TestSAMLServiceProviderKeyPair(t *testing.T) {
	certPEM, keyPEM, err := generateSAMLKeyPair("https://nexus.example.com/sso/provider")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if certificate.Subject.Organization[0] != "Netriun Nexus" || certificate.NotAfter.Sub(certificate.NotBefore) < 4*365*24*60*60*1e9 {
		t.Fatal("generated SAML certificate has unexpected identity or validity")
	}
}

func TestClaimValues(t *testing.T) {
	claims := map[string]any{"email": "person@example.com", "realm": map[string]any{"groups": []any{"operators", "platform", 3}}}
	if got := firstClaim(claims, "email"); got != "person@example.com" {
		t.Fatalf("email claim = %q", got)
	}
	groups := claimValues(claims, "realm.groups")
	if len(groups) != 2 || groups[0] != "operators" || groups[1] != "platform" {
		t.Fatalf("groups = %#v", groups)
	}
}
