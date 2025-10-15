// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package metrics

import (
	"net/http"
	"strconv"
	"time"
)

// HTTPMiddleware sets up a HTTP middleware for a prometheus service.
func (s *PromService) HTTPMiddleware(pathLabel string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(ww, r)
		code := strconv.Itoa(ww.code)
		s.HTTPRequests.WithLabelValues(r.Method, pathLabel, code).Inc()
		s.HTTPDurations.WithLabelValues(r.Method, pathLabel, code).Observe(time.Since(start).Seconds())
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }
