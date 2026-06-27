package proxy

import (
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
)

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	nonce := q.Get("nonce")
	responseType := q.Get("response_type")

	if clientID != s.cfg.ClientID {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}
	if redirectURI != s.cfg.RedirectURI {
		http.Error(w, "redirect_uri mismatch", http.StatusBadRequest)
		return
	}
	if responseType != "code" {
		writeOAuthError(w, redirectURI, state, "unsupported_response_type", "only code flow supported")
		return
	}

	pkceVerifier := oauth2.GenerateVerifier()

	stateID := s.states.storePending(&pendingAuth{
		clientRedirectURI: redirectURI,
		clientState:       state,
		clientNonce:       nonce,
		pkceVerifier:      pkceVerifier,
	})

	authURL := s.upstreamCfg.AuthCodeURL(
		stateID,
		oauth2.S256ChallengeOption(pkceVerifier),
		oauth2.SetAuthURLParam("nonce", nonce),
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func writeOAuthError(w http.ResponseWriter, redirectURI, state, code, desc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, code+": "+desc, http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", desc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	w.Header().Set("Location", u.String())
	w.WriteHeader(http.StatusFound)
}
