// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/require"
)

func TestNewService_RegistersStandardCollectors(t *testing.T) {
	s := NewPromService(Options{Namespace: "ion"})
	s.HTTPRequests.WithLabelValues("GET", "metrics", "200").Inc()
	s.HTTPDurations.WithLabelValues("GET", "metrics", "200").Observe(0.001)

	h := promhttp.HandlerFor(s.Registry(), promhttp.HandlerOpts{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()

	require.Contains(t, body, "go_goroutines")
	if runtime.GOOS != "js" && runtime.GOARCH != "wasm" {
		require.Contains(t, body, "process_cpu_seconds_total")
	}
	require.Contains(t, body, "ion_http_requests_total")
	require.Contains(t, body, "ion_http_request_duration_seconds")
}

func TestHandler_NoAuth_ServesMetrics(t *testing.T) {
	s := NewPromService(Options{Namespace: "ion"})
	h := s.Handler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Header().Get("Content-Type"), "text/plain")
	_, err := io.ReadAll(w.Body)
	require.NoError(t, err)
}

func TestNewService_With_Middleware(t *testing.T) {
	service := NewPromService(Options{Namespace: "ion"})

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := service.HTTPMiddleware("metrics", next)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	scr := httptest.NewRecorder()
	service.Handler().ServeHTTP(scr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, scr.Code)
	body := scr.Body.String()

	require.Contains(t, body, "go_goroutines")
	if runtime.GOOS != "js" && runtime.GOARCH != "wasm" {
		require.Contains(t, body, "process_cpu_seconds_total")
	}

	require.Contains(t, body, "ion_http_requests_total")
	require.Contains(t, body, "ion_http_request_duration_seconds_bucket")
	require.Contains(t, body, "ion_http_request_duration_seconds_sum")
	require.Contains(t, body, "ion_http_request_duration_seconds_count")
}
