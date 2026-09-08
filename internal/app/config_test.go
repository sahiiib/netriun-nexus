package app

import (
	"net/http/httptest"
	"testing"
)

func TestClientIPOnlyTrustsConfiguredProxies(t *testing.T) {
	proxies, err := parseTrustedProxies("127.0.0.1/32, 10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	a := &App{TrustedProxies: proxies}

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "198.51.100.7, 10.1.2.3")
	if got := a.clientIP(r); got != "198.51.100.7" {
		t.Fatalf("trusted proxy chain: got %q", got)
	}

	r.RemoteAddr = "203.0.113.8:1234"
	r.Header.Set("X-Forwarded-For", "198.51.100.7")
	if got := a.clientIP(r); got != "203.0.113.8" {
		t.Fatalf("untrusted peer spoofed client IP: got %q", got)
	}

	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "not-an-ip")
	if got := a.clientIP(r); got != "127.0.0.1" {
		t.Fatalf("invalid forwarded header: got %q", got)
	}
}

func TestParseTrustedProxies(t *testing.T) {
	proxies, err := parseTrustedProxies("127.0.0.1, 2001:db8::/32")
	if err != nil || len(proxies) != 2 {
		t.Fatalf("valid proxies rejected: count=%d err=%v", len(proxies), err)
	}
	if _, err = parseTrustedProxies("all-proxies"); err == nil {
		t.Fatal("invalid proxy entry accepted")
	}
}

func TestRuntimeConfigValidation(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://example")
	t.Setenv("REDIS_URL", "redis://example")
	t.Setenv("ENCRYPTION_KEY", "key-is-validated-by-the-vault")
	t.Setenv("APP_ORIGIN", "http://localhost:8080/")
	t.Setenv("COOKIE_SECURE", "false")
	t.Setenv("TRUSTED_PROXY_CIDRS", "")
	cfg, err := loadRuntimeConfig()
	if err != nil || cfg.origin != "http://localhost:8080" || cfg.secureCookies {
		t.Fatalf("valid local config rejected: cfg=%+v err=%v", cfg, err)
	}

	t.Setenv("APP_ORIGIN", "https://nexus.example.com")
	if _, err = loadRuntimeConfig(); err == nil {
		t.Fatal("insecure cookie accepted for an HTTPS origin")
	}
	t.Setenv("COOKIE_SECURE", "true")
	t.Setenv("APP_ORIGIN", "https://nexus.example.com/path")
	if _, err = loadRuntimeConfig(); err == nil {
		t.Fatal("origin containing a path accepted")
	}
}
