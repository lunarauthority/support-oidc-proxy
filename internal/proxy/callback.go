package proxy

import (
	"context"
	"log/slog"
	"net/http"

	"golang.org/x/oauth2"
)

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	stateID := q.Get("state")
	upstreamCode := q.Get("code")
	errParam := q.Get("error")

	pending, ok := s.states.takePending(stateID)
	if !ok {
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}

	if errParam != "" {
		writeOAuthError(w, pending.clientRedirectURI, pending.clientState,
			errParam, q.Get("error_description"))
		return
	}
	if upstreamCode == "" {
		writeOAuthError(w, pending.clientRedirectURI, pending.clientState,
			"invalid_request", "missing code")
		return
	}

	token, err := s.upstreamCfg.Exchange(
		context.Background(),
		upstreamCode,
		oauth2.VerifierOption(pending.pkceVerifier),
	)
	if err != nil {
		slog.Error("upstream token exchange failed", "err", err)
		writeOAuthError(w, pending.clientRedirectURI, pending.clientState,
			"server_error", "upstream token exchange failed")
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		slog.Error("upstream token response missing id_token")
		writeOAuthError(w, pending.clientRedirectURI, pending.clientState,
			"server_error", "upstream id_token missing")
		return
	}

	idToken, err := s.upstreamVerifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		slog.Error("upstream id_token verification failed", "err", err)
		writeOAuthError(w, pending.clientRedirectURI, pending.clientState,
			"server_error", "upstream token verification failed")
		return
	}

	var upstreamClaims struct {
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
		Name              string `json:"name"`
	}
	if err := idToken.Claims(&upstreamClaims); err != nil {
		slog.Error("upstream claims extraction failed", "err", err)
		writeOAuthError(w, pending.clientRedirectURI, pending.clientState,
			"server_error", "claims extraction failed")
		return
	}

	proxyCode := s.states.storeCode(&issuedCode{
		kanidmUUID:        idToken.Subject,
		preferredUsername: upstreamClaims.PreferredUsername,
		email:             upstreamClaims.Email,
		displayName:       upstreamClaims.Name,
		nonce:             pending.clientNonce,
	})

	target := pending.clientRedirectURI + "?code=" + proxyCode
	if pending.clientState != "" {
		target += "&state=" + pending.clientState
	}
	http.Redirect(w, r, target, http.StatusFound)
}
