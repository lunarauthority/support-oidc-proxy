package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type signingKey struct {
	priv *ecdsa.PrivateKey
	kid  string
}

func loadSigningKey(path string) (*signingKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC key: %w", err)
	}
	if priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("signing key must be P-256")
	}
	kid := fmt.Sprintf("%x", priv.PublicKey.X.Bytes()[:8])
	return &signingKey{priv: priv, kid: kid}, nil
}

func (k *signingKey) JWKS() *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       &k.priv.PublicKey,
				KeyID:     k.kid,
				Algorithm: string(jose.ES256),
				Use:       "sig",
			},
		},
	}
}

func (k *signingKey) IssueIDToken(issuer, subject, audience, preferredUsername, email, displayName, nonce string, ttl time.Duration) (string, error) {
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: k.priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", k.kid),
	)
	if err != nil {
		return "", fmt.Errorf("new signer: %w", err)
	}

	now := time.Now()
	claims := map[string]any{
		"iss":                issuer,
		"sub":                subject,
		"aud":                audience,
		"iat":                jwt.NewNumericDate(now),
		"exp":                jwt.NewNumericDate(now.Add(ttl)),
		"preferred_username": preferredUsername,
		"email":              email,
		"name":               displayName,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}

	raw, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return raw, nil
}

func (k *signingKey) ParseClaims(raw string) (map[string]any, error) {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("parse jwt: %w", err)
	}
	var claims map[string]any
	if err := tok.Claims(&k.priv.PublicKey, &claims); err != nil {
		return nil, fmt.Errorf("verify jwt: %w", err)
	}
	return claims, nil
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func MarshalKeyPEM(priv *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}
