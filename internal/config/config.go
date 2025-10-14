// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package config provides the config functionality for the ion project.
package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type (
	LogFormat  string
	WriterType string
)

var (
	ErrInvalidWriterType = errors.New("invalid writer type")
	ErrInvalidFormatType = errors.New("invalid format type")
)

const (
	LogFormatText LogFormat  = "text"
	LogFormatJSON LogFormat  = "json"
	WriterStderr  WriterType = "stderr"
	WriterStdout  WriterType = "stdout"
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

type OTLPMetricsConfig struct {
	Endpoint string `mapstructure:"endpoint"`
	Enabled  bool   `mapstructure:"enabled"`
}

type TelemetryMetricsConfig struct {
	Prometheus PrometheusConfig  `mapstructure:"prometheus"`
	OTLP       OTLPMetricsConfig `mapstructure:"otlp"`
}

type OTLPTracesConfig struct {
	ServiceName string  `mapstructure:"service_name"`
	Endpoint    string  `mapstructure:"endpoint"`
	SampleRatio float64 `mapstructure:"sample_ratio"`
	Enabled     bool    `mapstructure:"enabled"`
}

type TelemetryTracesConfig struct {
	OTLP OTLPTracesConfig
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
				OTLP: OTLPMetricsConfig{
					Enabled:  false,
					Endpoint: DefaultOTLPEndpoint,
				},
			},
			Traces: TelemetryTracesConfig{
				OTLP: OTLPTracesConfig{
					Enabled:     false,
					ServiceName: DefaultServiceName,
					Endpoint:    DefaultOTLPEndpoint,
					SampleRatio: DefaultTraceSample,
				},
			},
		},
	}
}

func RegisterFlags(fs *pflag.FlagSet) {
	def := DefaultConfig()

	// config file
	fs.String("config", "", "Path to config file (TOML)")

	// telemetry.logs
	fs.String("telemetry.logs.level", def.Telemetry.Logs.Level,
		"Log level (debug|info|warn|error)")
	fs.String("telemetry.logs.format", string(def.Telemetry.Logs.Format),
		"Log format (text|json)")

	// telemetry.metrics.prometheus
	fs.Bool("telemetry.metrics.prometheus.enabled", def.Telemetry.Metrics.Prometheus.Enabled,
		"Enable Prometheus metrics exporter (scrape endpoint)")
	fs.String("telemetry.metrics.prometheus.addr", def.Telemetry.Metrics.Prometheus.Addr,
		"Prometheus metrics bind address (host:port or :port)")

	// telemetry.metrics.otlp
	fs.Bool("telemetry.metrics.otlp.enabled", def.Telemetry.Metrics.OTLP.Enabled,
		"Enable OTLP metrics exporter (push)")
	fs.String("telemetry.metrics.otlp.endpoint", def.Telemetry.Metrics.OTLP.Endpoint,
		"OTLP metrics endpoint (e.g. host:4317)")

	// telemetry.traces.otlp
	fs.Bool("telemetry.traces.otlp.enabled", def.Telemetry.Traces.OTLP.Enabled,
		"Enable OpenTelemetry tracing via OTLP")
	fs.String("telemetry.traces.otlp.service_name", def.Telemetry.Traces.OTLP.ServiceName,
		"Tracing service name")
	fs.String("telemetry.traces.otlp.endpoint", def.Telemetry.Traces.OTLP.Endpoint,
		"OTLP traces endpoint (e.g. host:4317)")
	fs.Float64("telemetry.traces.otlp.sample_ratio", def.Telemetry.Traces.OTLP.SampleRatio,
		"Tracing sampler ratio in [0.0,1.0]")
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

	vp.SetDefault("telemetry.traces.otlp.enabled", cfg.Telemetry.Traces.OTLP.Enabled)
	vp.SetDefault("telemetry.traces.otlp.service_name", cfg.Telemetry.Traces.OTLP.ServiceName)
	vp.SetDefault("telemetry.traces.otlp.endpoint", cfg.Telemetry.Traces.OTLP.Endpoint)
	vp.SetDefault("telemetry.traces.otlp.sample_ratio", cfg.Telemetry.Traces.OTLP.SampleRatio)

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
