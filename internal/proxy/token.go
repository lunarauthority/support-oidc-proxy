package proxy

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const idTokenTTL = time.Hour

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, "invalid_request", "cannot parse form")
		return
	}

	if !s.validateClientCredentials(r) {
		w.Header().Set("WWW-Authenticate", `Basic realm="support-oidc-proxy"`)
		writeTokenError(w, "invalid_client", "invalid client credentials")
		return
	}

	if r.FormValue("grant_type") != "authorization_code" {
		writeTokenError(w, "unsupported_grant_type", "only authorization_code supported")
		return
	}

	code := r.FormValue("code")
	issued, ok := s.states.takeCode(code)
	if !ok {
		writeTokenError(w, "invalid_grant", "code not found or expired")
		return
	}

	idToken, err := s.key.IssueIDToken(
		s.cfg.IssuerURL,
		issued.kanidmUUID,
		s.cfg.ClientID,
		issued.preferredUsername,
		issued.email,
		issued.displayName,
		issued.nonce,
		idTokenTTL,
	)
	if err != nil {
		slog.Error("token issuance failed", "err", err)
		writeTokenError(w, "server_error", "token issuance failed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(tokenResponse{ //nolint:errcheck
		AccessToken: idToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(idTokenTTL.Seconds()),
		IDToken:     idToken,
	})
}

func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if bearer == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}
	claims, err := s.key.ParseClaims(bearer)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(claims) //nolint:errcheck
}

func (s *Server) validateClientCredentials(r *http.Request) bool {
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if clientID == "" {
		if id, secret, ok := r.BasicAuth(); ok {
			clientID, clientSecret = id, secret
		}
	}
	return clientID == s.cfg.ClientID && clientSecret == s.cfg.ClientSecret
}

func writeTokenError(w http.ResponseWriter, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"error":             code,
		"error_description": desc,
	})
}
