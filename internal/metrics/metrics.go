// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

type Options struct {
	Namespace string
}

type PromService struct {
	reg           *prometheus.Registry
	HTTPRequests  *prometheus.CounterVec
	HTTPDurations *prometheus.HistogramVec
}

// NewPromService returns new prometheus service for Ion.
func NewPromService(opts Options) *PromService {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	req := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: opts.Namespace, Name: "http_requests_total",
		Help: "Total HTTP requests", ConstLabels: nil,
	}, []string{"method", "path", "code"})

	dur := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: opts.Namespace, Name: "http_request_duration_seconds",
		Help:    "HTTP request duration (s)",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path", "code"})

	reg.MustRegister(req, dur)

	return &PromService{reg: reg, HTTPRequests: req, HTTPDurations: dur}
}

// Registry returns the prometheus registory.
func (s *PromService) Registry() *prometheus.Registry { return s.reg }
