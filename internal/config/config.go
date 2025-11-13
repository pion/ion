// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package config provides the config functionality for the ion project.
package config

import (
	"errors"
	"fmt"
	"strings"

	ionICE "github.com/pion/ion/v2/internal/ice"
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
	ICE       ionICE.ICEConfig
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
		ICE: ionICE.DefaultICEConfig(),
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

	// ice.stun
	fs.Bool("ice.stun.enabled", def.ICE.STUN.Enabled, "Enable embedded STUN server")
	fs.String("ice.stun.udp_endpoint", def.ICE.STUN.UDPEndpoint, "STUN UDP bind (host:port or :port)")
	fs.String("ice.stun.tcp_endpoint", def.ICE.STUN.TCPEndpoint, "STUN TCP bind (host:port or :port)")

	// ice.turn
	fs.Bool("ice.turn.enabled", def.ICE.TURN.Enabled, "Enable embedded TURN server")
	fs.String("ice.turn.udp_endpoint", def.ICE.TURN.UDPEndpoint, "TURN UDP bind (host:port or :port)")
	fs.String("ice.turn.tcp_endpoint", def.ICE.TURN.TCPEndpoint, "TURN TCP bind (host:port or :port)")
	fs.String("ice.turn.public_ip", def.ICE.TURN.PublicIP, "Public IP return to TURN client")
	fs.String("ice.turn.realm", def.ICE.TURN.Realm, "TURN realm")
	fs.String("ice.turn.auth", def.ICE.TURN.Auth, "TURN auth mode (long-term|static)")
	fs.String("ice.turn.user", def.ICE.TURN.User, "TURN static username (for long-term auth)")
	fs.String("ice.turn.password", def.ICE.TURN.Password, "TURN static password (for long-term auth)")
	fs.String("ice.turn.secret", def.ICE.TURN.Secret, "TURN shared secret (for time-limited creds)")
	fs.Uint16("ice.turn.port_range_min", def.ICE.TURN.PortRangeMin, "TURN min port range")
	fs.Uint16("ice.turn.port_range_max", def.ICE.TURN.PortRangeMin, "TURN max port range")
	fs.String("ice.turn.address", def.ICE.TURN.Address, "TURN address")

	// ice.turn.tls
	fs.String("ice.turn.tls.endpoint", def.ICE.TURN.TLS.Endpoint, "TURN TLS bind (host:port or :port)")
	fs.String("ice.turn.tls.cert", def.ICE.TURN.TLS.Cert, "TURN TLS certificate file path")
	fs.String("ice.turn.tls.key", def.ICE.TURN.TLS.Key, "TURN TLS private key file path")
	fs.String("ice.turn.tls.version", def.ICE.TURN.TLS.Version, "TURN TLS version (TLS12|TLS13)")
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

	vp.SetDefault("ice.stun.enabled", cfg.ICE.STUN.Enabled)
	vp.SetDefault("ice.stun.udp_endpoint", cfg.ICE.STUN.UDPEndpoint)
	vp.SetDefault("ice.stun.tcp_endpoint", cfg.ICE.STUN.TCPEndpoint)

	vp.SetDefault("ice.turn.enabled", cfg.ICE.TURN.Enabled)
	vp.SetDefault("ice.turn.udp_endpoint", cfg.ICE.TURN.UDPEndpoint)
	vp.SetDefault("ice.turn.tcp_endpoint", cfg.ICE.TURN.TCPEndpoint)
	vp.SetDefault("ice.turn.public_ip", (cfg.ICE.TURN.PublicIP))
	vp.SetDefault("ice.turn.realm", cfg.ICE.TURN.Realm)
	vp.SetDefault("ice.turn.auth", cfg.ICE.TURN.Auth)
	vp.SetDefault("ice.turn.user", cfg.ICE.TURN.User)
	vp.SetDefault("ice.turn.password", cfg.ICE.TURN.Password)
	vp.SetDefault("ice.turn.secret", cfg.ICE.TURN.Secret)
	vp.SetDefault("ice.turn.port_range_min", (cfg.ICE.TURN.PortRangeMin))
	vp.SetDefault("ice.turn.port_range_max", (cfg.ICE.TURN.PortRangeMax))
	vp.SetDefault("ice.turn.address", (cfg.ICE.TURN.Address))
	vp.SetDefault("ice.turn.tls.endpoint", (cfg.ICE.TURN.TLS.Endpoint))
	vp.SetDefault("ice.turn.tls.cert", (cfg.ICE.TURN.TLS.Cert))
	vp.SetDefault("ice.turn.tls.key", (cfg.ICE.TURN.TLS.Key))
	vp.SetDefault("ice.turn.tls.version", (cfg.ICE.TURN.TLS.Version))

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

	// Validate
	if err := cfg.ICE.Validate(); err != nil {
		return cfg, err
	}

	return cfg, nil
}
