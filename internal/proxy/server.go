package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Server struct {
	cfg              *Config
	key              *signingKey
	states           *stateStore
	upstreamCfg      *oauth2.Config
	upstreamVerifier *gooidc.IDTokenVerifier
	mux              *http.ServeMux
}

func New(cfg *Config) (*Server, error) {
	key, err := loadSigningKey(cfg.SigningKeyPath)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}

	provider, err := gooidc.NewProvider(context.Background(), cfg.UpstreamIssuer)
	if err != nil {
		return nil, fmt.Errorf("upstream OIDC provider: %w", err)
	}

	upstreamCfg := &oauth2.Config{
		ClientID:     cfg.UpstreamClientID,
		ClientSecret: cfg.UpstreamClientSecret,
		RedirectURL:  cfg.IssuerURL + "/callback",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{gooidc.ScopeOpenID, "profile", "email"},
	}

	verifier := provider.Verifier(&gooidc.Config{ClientID: cfg.UpstreamClientID})

	s := &Server{
		cfg:              cfg,
		key:              key,
		states:           newStateStore(),
		upstreamCfg:      upstreamCfg,
		upstreamVerifier: verifier,
		mux:              http.NewServeMux(),
	}
	s.registerRoutes()
	return s, nil
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)
	s.mux.HandleFunc("GET /jwks", s.handleJWKS)
	s.mux.HandleFunc("GET /authorize", s.handleAuthorize)
	s.mux.HandleFunc("GET /callback", s.handleCallback)
	s.mux.HandleFunc("POST /token", s.handleToken)
	s.mux.HandleFunc("GET /userinfo", s.handleUserinfo)
	s.mux.HandleFunc("POST /userinfo", s.handleUserinfo)
}

func (s *Server) ListenAndServe() error {
	addr := ":" + s.cfg.Port
	srv := &http.Server{
		Addr:         addr,
		Handler:      s.mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	slog.Info("support-oidc-proxy listening", "addr", addr, "issuer", s.cfg.IssuerURL)
	return srv.ListenAndServe()
}
