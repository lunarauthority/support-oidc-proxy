package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const (
	pendingTTL = 5 * time.Minute
	codeTTL    = 60 * time.Second
)

type pendingAuth struct {
	clientRedirectURI string
	clientState       string
	clientNonce       string
	pkceVerifier      string
	expiry            time.Time
}

type issuedCode struct {
	kanidmUUID        string
	preferredUsername string
	email             string
	displayName       string
	nonce             string
	expiry            time.Time
}

type stateStore struct {
	mu      sync.Mutex
	pending map[string]*pendingAuth
	codes   map[string]*issuedCode
}

func newStateStore() *stateStore {
	s := &stateStore{
		pending: make(map[string]*pendingAuth),
		codes:   make(map[string]*issuedCode),
	}
	go s.reap()
	return s
}

func (s *stateStore) storePending(p *pendingAuth) string {
	id := randomHex(16)
	p.expiry = time.Now().Add(pendingTTL)
	s.mu.Lock()
	s.pending[id] = p
	s.mu.Unlock()
	return id
}

func (s *stateStore) takePending(id string) (*pendingAuth, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[id]
	if !ok || time.Now().After(p.expiry) {
		delete(s.pending, id)
		return nil, false
	}
	delete(s.pending, id)
	return p, true
}

func (s *stateStore) storeCode(c *issuedCode) string {
	code := randomHex(24)
	c.expiry = time.Now().Add(codeTTL)
	s.mu.Lock()
	s.codes[code] = c
	s.mu.Unlock()
	return code
}

func (s *stateStore) takeCode(code string) (*issuedCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[code]
	if !ok || time.Now().After(c.expiry) {
		delete(s.codes, code)
		return nil, false
	}
	delete(s.codes, code)
	return c, true
}

func (s *stateStore) reap() {
	t := time.NewTicker(2 * time.Minute)
	for range t.C {
		now := time.Now()
		s.mu.Lock()
		for k, v := range s.pending {
			if now.After(v.expiry) {
				delete(s.pending, k)
			}
		}
		for k, v := range s.codes {
			if now.After(v.expiry) {
				delete(s.codes, k)
			}
		}
		s.mu.Unlock()
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
