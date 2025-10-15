// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package metrics provides service to expose Ion's metric.
package metrics

import (
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Auth struct {
	Mode       string // "none"|"basic"|"bearer"
	User, Pass string
	Token      string
}

// Handler returns a http handler wrapped with authentication.
func (s *PromService) Handler(auth Auth) http.Handler {
	h := promhttp.HandlerFor(s.reg, promhttp.HandlerOpts{})
	switch auth.Mode {
	case "basic":
		return basicAuth(h, auth.User, auth.Pass)
	case "bearer":
		return bearerAuth(h, auth.Token)
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
