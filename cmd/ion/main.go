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
	fmt.Printf("LOG: level=%s format=%s\n", cfg.Log.Level, cfg.Log.Format)
	fmt.Printf("METRICS: addr=%s\n", cfg.Metrics.Addr)
	fmt.Printf("HTTP: addr=%s\n", cfg.HTTP.Addr)

	fmt.Println(core.HelloWorld())
}
