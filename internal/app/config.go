package app

import (
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type runtimeConfig struct {
	databaseURL     string
	redisURL        string
	encryptionKey   string
	origin          string
	secureCookies   bool
	trustedProxies  []*net.IPNet
	smtpHost        string
	smtpPort        string
	smtpUsername    string
	smtpPassword    string
	smtpFromAddress string
	smtpFromName    string
}

func loadRuntimeConfig() (runtimeConfig, error) {
	var c runtimeConfig
	c.databaseURL = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	c.redisURL = strings.TrimSpace(os.Getenv("REDIS_URL"))
	c.encryptionKey = strings.TrimSpace(os.Getenv("ENCRYPTION_KEY"))
	if c.databaseURL == "" || c.redisURL == "" || c.encryptionKey == "" {
		return c, errors.New("DATABASE_URL, REDIS_URL and ENCRYPTION_KEY are required")
	}
	c.smtpHost = strings.TrimSpace(os.Getenv("SMTP_HOST"))
	c.smtpPort = strings.TrimSpace(os.Getenv("SMTP_PORT"))
	c.smtpUsername = strings.TrimSpace(os.Getenv("SMTP_USERNAME"))
	c.smtpPassword = strings.TrimSpace(os.Getenv("SMTP_PASSWORD"))
	c.smtpFromAddress = strings.TrimSpace(os.Getenv("SMTP_FROM_ADDRESS"))
	c.smtpFromName = strings.TrimSpace(os.Getenv("SMTP_FROM_NAME"))
	if c.smtpHost == "" || c.smtpPort == "" || c.smtpUsername == "" || c.smtpPassword == "" || c.smtpFromAddress == "" || c.smtpFromName == "" {
		return c, errors.New("SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM_ADDRESS and SMTP_FROM_NAME are required")
	}
	port, portErr := strconv.Atoi(c.smtpPort)
	if portErr != nil || port < 1 || port > 65535 {
		return c, errors.New("SMTP_PORT must be a valid TCP port")
	}

	origin, err := url.Parse(strings.TrimSpace(os.Getenv("APP_ORIGIN")))
	if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") || origin.Host == "" || origin.User != nil || (origin.Path != "" && origin.Path != "/") || origin.RawQuery != "" || origin.Fragment != "" {
		return c, errors.New("APP_ORIGIN must be an exact http(s) origin without a path, query or fragment")
	}
	c.origin = strings.TrimSuffix(origin.String(), "/")

	c.secureCookies = true
	if raw := strings.TrimSpace(os.Getenv("COOKIE_SECURE")); raw != "" {
		c.secureCookies, err = strconv.ParseBool(raw)
		if err != nil {
			return c, errors.New("COOKIE_SECURE must be true or false")
		}
	}
	if origin.Scheme == "https" && !c.secureCookies {
		return c, errors.New("COOKIE_SECURE must be true when APP_ORIGIN uses https")
	}

	c.trustedProxies, err = parseTrustedProxies(os.Getenv("TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return c, err
	}
	return c, nil
}

func parseTrustedProxies(raw string) ([]*net.IPNet, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var out []*net.IPNet
	for _, value := range strings.Split(raw, ",") {
		value = strings.TrimSpace(value)
		if ip := net.ParseIP(value); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			value += "/" + strconv.Itoa(bits)
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, errors.New("TRUSTED_PROXY_CIDRS must be a comma-separated list of IP addresses or CIDRs")
		}
		out = append(out, network)
	}
	return out, nil
}
