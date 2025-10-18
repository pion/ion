// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package metrics provides service to expose Ion's metric.
package metrics

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/bcrypt"
)

type hashingMethod int

const (
	HashingNone hashingMethod = iota
	HashingBcrypt
	HashingSHA256
)

func (e hashingMethod) String() string {
	switch e {
	case HashingBcrypt:
		return "bcrypt"
	case HashingSHA256:
		return "sha256"
	default:
		return "none"
	}
}

type authConfig struct {
	user            string
	pass            string
	token           string
	passHashMethod  hashingMethod
	tokenHashMethod hashingMethod
	hasBasicAuth    bool
	hasBearerToken  bool
}

type Option func(*authConfig)

func WithBasicAuth(user, pass string, hashingMethod hashingMethod) Option {
	return func(c *authConfig) {
		c.hasBasicAuth = true
		c.user = user
		c.pass = pass
		c.passHashMethod = hashingMethod
	}
}

func WithBearerToken(token string, hashingMethod hashingMethod) Option {
	return func(c *authConfig) {
		c.hasBearerToken = true
		c.token = token
		c.tokenHashMethod = hashingMethod
	}
}

func (s *PromService) Handler(opts ...Option) http.Handler {
	cfg := authConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	h := promhttp.HandlerFor(s.reg, promhttp.HandlerOpts{})

	if !cfg.hasBasicAuth && !cfg.hasBearerToken {
		return h
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authenticateRequest(w, r, cfg) {
			h.ServeHTTP(w, r)
		}
	})
}

// authenticateRequest attempts to authenticate the request using Basic Auth or Bearer Token.
// Returns true if authentication succeeds, false otherwise.
func authenticateRequest(writer http.ResponseWriter, request *http.Request, cfg authConfig) bool {
	if cfg.hasBasicAuth {
		user, pass, ok := request.BasicAuth()
		if ok && user == cfg.user && compareSecret(pass, cfg.pass, cfg.passHashMethod) {
			return true
		}
	}

	if cfg.hasBearerToken {
		token, ok := extractBearerToken(request)
		if ok && compareSecret(token, cfg.token, cfg.tokenHashMethod) {
			return true
		}
	}

	if cfg.hasBasicAuth {
		unauthorizedBasic(writer)
	} else if cfg.hasBearerToken {
		unauthorized(writer)
	}

	return false
}

func unauthorizedBasic(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="metrics"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// extractBearerToken extracts the bearer token from the Authorization header.
// The bearer scheme is case-insensitive per RFC 7235.
func extractBearerToken(r *http.Request) (string, bool) {
	const bearerPrefix = "bearer "

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(authHeader), bearerPrefix) {
		return "", false
	}

	token := strings.TrimSpace(authHeader[len(bearerPrefix):])

	return token, true
}

// compareSecret compares a provided secret against an expected one using the specified hashing method.
func compareSecret(provided, expected string, method hashingMethod) bool {
	switch method {
	case HashingBcrypt:
		return compareBcrypt(provided, expected)
	case HashingSHA256:
		return compareSHA256(provided, expected)
	default:
		return compareRaw(provided, expected)
	}
}

func compareBcrypt(left, right string) bool {
	const bcryptLength = 32
	hashedBytes, err := hex.DecodeString(right)
	if err != nil {
		compareDummy(bcryptLength)

		return false
	}

	return bcrypt.CompareHashAndPassword(hashedBytes, []byte(left)) == nil
}

func compareSHA256(left, right string) bool {
	sum := sha256.Sum256([]byte(left))
	rightBytes, err := hex.DecodeString(right)
	if err != nil || len(rightBytes) != len(sum) {
		compareDummy(len(sum))

		return false
	}

	return subtle.ConstantTimeCompare(sum[:], rightBytes) == 1
}

func compareRaw(provided, expected string) bool {
	leftBytes := []byte(provided)
	rightBytes := []byte(expected)
	if len(provided) != len(expected) {
		compareDummy(len(expected))

		return false
	}

	return subtle.ConstantTimeCompare(leftBytes, rightBytes) == 1
}

// compareDummy burn time with a constant-time compare on dummy.
func compareDummy(length int) {
	d1 := make([]byte, length)
	d2 := make([]byte, length)
	for i := range d2 {
		d2[i] = 1
	}

	subtle.ConstantTimeCompare(d1, d2)
}
