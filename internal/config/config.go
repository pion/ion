// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package config provides the config functionality for the ion project.
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type LogFormat string

const (
	LogFormatText LogFormat = "text"
	LogFormatJSON LogFormat = "json"
)

const (
	DefaultLogLevel       = "info"
	DefaultLogFormat      = LogFormatText
	DefaultPrometheusAddr = ":2112"
	DefaultOTLPEndpoint   = ""
	DefaultTraceSample    = 0.0
	DefaultServiceName    = "ion"
)

type TelemetryLogsConfig struct {
	Level  string    `mapstructure:"level"`
	Format LogFormat `mapstructure:"format"`
}

type PrometheusConfig struct {
	Addr    string `mapstructure:"addr"`
	Enabled bool   `mapstructure:"enabled"`
}

type OTLPConfig struct {
	Endpoint string `mapstructure:"endpoint"`
	Enabled  bool   `mapstructure:"enabled"`
}

type TelemetryMetricsConfig struct {
	Prometheus PrometheusConfig `mapstructure:"prometheus"`
	OTLP       OTLPConfig       `mapstructure:"otlp"`
}

type TelemetryTracesConfig struct {
	ServiceName  string  `mapstructure:"service_name"`
	OTLPEndpoint string  `mapstructure:"otlp_endpoint"`
	SampleRatio  float64 `mapstructure:"sample_ratio"`
	Enabled      bool    `mapstructure:"enabled"`
}

type TelemetryConfig struct {
	Logs    TelemetryLogsConfig    `mapstructure:"logs"`
	Metrics TelemetryMetricsConfig `mapstructure:"metrics"`
	Traces  TelemetryTracesConfig  `mapstructure:"traces"`
}

type Config struct {
	Telemetry TelemetryConfig `mapstructure:"telemetry"`
}

func DefaultConfig() Config {
	return Config{
		Telemetry: TelemetryConfig{
			Logs: TelemetryLogsConfig{
				Level:  DefaultLogLevel,
				Format: DefaultLogFormat,
			},
			Metrics: TelemetryMetricsConfig{
				Prometheus: PrometheusConfig{
					Enabled: false,
					Addr:    DefaultPrometheusAddr,
				},
				OTLP: OTLPConfig{
					Enabled:  false,
					Endpoint: DefaultOTLPEndpoint,
				},
			},
			Traces: TelemetryTracesConfig{
				Enabled:      false,
				ServiceName:  DefaultServiceName,
				OTLPEndpoint: DefaultOTLPEndpoint,
				SampleRatio:  DefaultTraceSample,
			},
		},
	}
}

func RegisterFlags(fs *pflag.FlagSet) {
	def := DefaultConfig()

	// config file
	fs.String("config", "", "Path to config file (TOML)")

	// telemetry.logs
	fs.String("telemetry.logs.level", def.Telemetry.Logs.Level, "Log level (debug|info|warn|error)")
	fs.String("telemetry.logs.format", string(def.Telemetry.Logs.Format), "Log format (text|json)")

	// telemetry.metrics.prometheus
	fs.Bool("telemetry.metrics.prometheus.enabled", def.Telemetry.Metrics.Prometheus.Enabled,
		"Enable Prometheus metrics exporter (scrape endpoint)")
	fs.String("telemetry.metrics.prometheus.addr", def.Telemetry.Metrics.Prometheus.Addr,
		"Prometheus metrics bind address (host:port or :port)")

	// telemetry.metrics.otlp
	fs.Bool("telemetry.metrics.otlp.enabled", def.Telemetry.Metrics.OTLP.Enabled, "Enable OTLP metrics exporter (push)")
	fs.String("telemetry.metrics.otlp.endpoint", def.Telemetry.Metrics.OTLP.Endpoint,
		"OTLP metrics endpoint (e.g. host:4317)")

	// telemetry.traces
	fs.Bool("telemetry.traces.enabled", def.Telemetry.Traces.Enabled, "Enable OpenTelemetry tracing")
	fs.String("telemetry.traces.service_name", def.Telemetry.Traces.ServiceName, "Tracing service name")
	fs.String("telemetry.traces.otlp_endpoint", def.Telemetry.Traces.OTLPEndpoint, "OTLP traces endpoint (e.g. host:4317)")
	fs.Float64("telemetry.traces.sample_ratio", def.Telemetry.Traces.SampleRatio, "Tracing sampler ratio in [0.0,1.0]")
}

// Load returns config struct for ION.
func Load(fs *pflag.FlagSet) (Config, error) {
	cfg := DefaultConfig()
	vp := viper.New()

	// Defaults
	vp.SetDefault("telemetry.logs.level", cfg.Telemetry.Logs.Level)
	vp.SetDefault("telemetry.logs.format", cfg.Telemetry.Logs.Format)

	vp.SetDefault("telemetry.metrics.prometheus.enabled", cfg.Telemetry.Metrics.Prometheus.Enabled)
	vp.SetDefault("telemetry.metrics.prometheus.addr", cfg.Telemetry.Metrics.Prometheus.Addr)

	vp.SetDefault("telemetry.metrics.otlp.enabled", cfg.Telemetry.Metrics.OTLP.Enabled)
	vp.SetDefault("telemetry.metrics.otlp.endpoint", cfg.Telemetry.Metrics.OTLP.Endpoint)

	vp.SetDefault("telemetry.traces.enabled", cfg.Telemetry.Traces.Enabled)
	vp.SetDefault("telemetry.traces.service_name", cfg.Telemetry.Traces.ServiceName)
	vp.SetDefault("telemetry.traces.otlp_endpoint", cfg.Telemetry.Traces.OTLPEndpoint)
	vp.SetDefault("telemetry.traces.sample_ratio", cfg.Telemetry.Traces.SampleRatio)

	// Env
	vp.SetEnvPrefix("ION")
	vp.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	vp.AutomaticEnv()

	// Flags
	if fs != nil {
		fs.VisitAll(func(f *pflag.Flag) {
			if f.Name != "config" {
				_ = vp.BindPFlag(f.Name, f) // Skip config path flag
			}
		})
	}

	// If config file is set, read it
	var cfgPath string
	if fs != nil {
		if f := fs.Lookup("config"); f != nil {
			cfgPath = f.Value.String()
		}
	}
	if cfgPath != "" {
		vp.SetConfigFile(cfgPath)
		if err := vp.ReadInConfig(); err != nil {
			return Config{}, fmt.Errorf("failed to read config %q: %w", cfgPath, err)
		}
	}

	if err := vp.UnmarshalExact(&cfg); err != nil {
		return Config{}, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return cfg, nil
}
