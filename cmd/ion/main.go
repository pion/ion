// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/pion/ion/v2/internal/config"
	"github.com/pion/ion/v2/internal/core"
	"github.com/pion/ion/v2/internal/logger"
	"github.com/pion/ion/v2/internal/metrics"
	"github.com/spf13/pflag"
)

func main() {
	config.RegisterFlags(pflag.CommandLine)
	pflag.Parse()
	cfg, err := config.Load(pflag.CommandLine)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("LOG: level=%s format=%s\n", cfg.Telemetry.Logs.Level, cfg.Telemetry.Logs.Format)
	fmt.Printf("METRICS PROMETHEUS: addr=%s\n", cfg.Telemetry.Metrics.Prometheus.Addr)
	fmt.Printf("TRACE OTLP: service name=%s\n", cfg.Telemetry.Traces.OTLP.ServiceName)
	logFactory, err := logger.NewLoggerFactory(
		logger.Options{
			DefaultWriter: config.WriterStderr,
			Format:        config.LogFormatText,
			ScopeLevels: map[string]string{
				"sfu":    "debug",
				"signal": "error",
			},
			DefaultLevel: "debug",
		},
	)
	if err != nil {
		panic(err)
	}
	ctx := context.Background()
	ctxSignal := logFactory.BuildLoggerForCtx(ctx, "signal")
	ctxSfu := logFactory.BuildLoggerForCtx(ctx, "sfu")
	// Signal not printed due to error level
	sigLogger := logFactory.FromCtx(ctxSignal)
	sigLogger.InfoContext(ctxSignal, "Start signaling")
	// Sfu printed due to debug level
	sfuLogger := logFactory.FromCtx(ctxSfu)
	sfuLogger.InfoContext(ctxSfu, "Starting SFU")

	fmt.Println(ctxSignal)
	fmt.Println(core.HelloWorld())

	mux := http.NewServeMux()
	if cfg.Telemetry.Metrics.Prometheus.Enabled {
		m := metrics.NewPromService(metrics.Options{Namespace: "ion"})
		mux.Handle("/metrics", m.HTTPMiddleware("metrics",
			m.Handler()))
		srv := &http.Server{
			Addr:              cfg.Telemetry.Metrics.Prometheus.Addr,
			Handler:           mux,
			ReadHeaderTimeout: time.Second,
		}
		_ = srv.ListenAndServe()
	}
}
