// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package metrics provides service to expose Ion's metric.
package metrics

import (
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type authMode int

const (
	modeNone authMode = iota
	modeBasic
	modeBearer
)

type authConfig struct {
	user  string
	pass  string
	token string
	mode  authMode
}

type Option func(*authConfig)

func WithBasicAuth(user, pass string) Option {
	return func(c *authConfig) {
		c.mode = modeBasic
		c.user = user
		c.pass = pass
	}
}

func WithBearerToken(token string) Option {
	return func(c *authConfig) {
		c.mode = modeBearer
		c.token = token
	}
}

func (s *PromService) Handler(opts ...Option) http.Handler {
	cfg := authConfig{mode: modeNone}
	for _, opt := range opts {
		opt(&cfg)
	}

	h := promhttp.HandlerFor(s.reg, promhttp.HandlerOpts{})

	switch cfg.mode {
	case modeBasic:
		return basicAuth(h, cfg.user, cfg.pass)
	case modeBearer:
		return bearerAuth(h, cfg.token)
	default:
		return h
	}
}

// BasicAuth implements a naive user pwd authentication.
func basicAuth(next http.Handler, user, pwd string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != user || p != pwd {
			w.Header().Set("WWW-Authenticate", `Basic realm="metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)

			return
		}
		next.ServeHTTP(w, r)
	})
}

// BearerAuth implements a naive token based authentication.
func bearerAuth(next http.Handler, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold("Bearer "+token, r.Header.Get("Authorization")) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)

			return
		}
		next.ServeHTTP(w, r)
	})
}
