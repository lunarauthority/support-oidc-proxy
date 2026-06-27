package proxy

import (
	"fmt"
	"os"
)

type Config struct {
	IssuerURL      string
	UpstreamIssuer string

	UpstreamClientID     string
	UpstreamClientSecret string

	// ClientID and ClientSecret are the credentials the proxy issues to OpenProject.
	// OpenProject sends these on every token request; the proxy validates them.
	ClientID     string
	ClientSecret string

	// RedirectURI is the OpenProject OIDC callback the proxy redirects to after
	// completing the Kanidm auth exchange.
	RedirectURI string

	SigningKeyPath string
	Port          string
}

func ConfigFromEnv() (*Config, error) {
	c := &Config{
		IssuerURL:            getEnv("ISSUER_URL", ""),
		UpstreamIssuer:       getEnv("UPSTREAM_ISSUER", ""),
		UpstreamClientID:     getEnv("UPSTREAM_CLIENT_ID", ""),
		UpstreamClientSecret: getEnv("UPSTREAM_CLIENT_SECRET", ""),
		ClientID:             getEnv("CLIENT_ID", ""),
		ClientSecret:         getEnv("CLIENT_SECRET", ""),
		RedirectURI:          getEnv("REDIRECT_URI", ""),
		SigningKeyPath:        getEnv("SIGNING_KEY_PATH", "/run/secrets/signing-key/private.pem"),
		Port:                 getEnv("PORT", "8080"),
	}

	for _, pair := range []struct{ name, val string }{
		{"ISSUER_URL", c.IssuerURL},
		{"UPSTREAM_ISSUER", c.UpstreamIssuer},
		{"UPSTREAM_CLIENT_ID", c.UpstreamClientID},
		{"UPSTREAM_CLIENT_SECRET", c.UpstreamClientSecret},
		{"CLIENT_ID", c.ClientID},
		{"CLIENT_SECRET", c.ClientSecret},
		{"REDIRECT_URI", c.RedirectURI},
	} {
		if pair.val == "" {
			return nil, fmt.Errorf("required env var %s is not set", pair.name)
		}
	}
	return c, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
