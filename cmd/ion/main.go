// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"

	"github.com/pion/ion/v2/internal/config"
	"github.com/pion/ion/v2/internal/core"
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

	fmt.Println(core.HelloWorld())
}
