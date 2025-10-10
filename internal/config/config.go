// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package config provides the config functionality for the ion project.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type LogFormat string

const (
	LogFormatText LogFormat = "text"
	LogFormatJSON LogFormat = "json"
)

const (
	DefaultLogLevel            = "info"
	DefaultLogFormat           = LogFormatText
	DefaultMetricsAddr         = ":2112"
	DefaultHTTPAddr            = ":8080"
	DefaultTracingSample       = 0.0
	DefaultSignalingTimeout    = 10 * time.Second
	DefaultMaxPublishBitrate   = 1_500_000
	DefaultMaxSubscribeBitrate = 2_500_000
	DefaultWebRTCMTU           = 1200
)

type LogConfig struct {
	Level  string    `mapstructure:"level"`
	Format LogFormat `mapstructure:"format"`
}

type MetricsConfig struct {
	Addr string `mapstructure:"addr"`
}

type HTTPConfig struct {
	Addr string `mapstructure:"addr"`
}

type TracingConfig struct {
	ServiceName  string  `mapstructure:"service_name"`
	OTLPEndpoint string  `mapstructure:"otlp_endpoint"`
	SampleRatio  float64 `mapstructure:"sample_ratio"`
	Enabled      bool    `mapstructure:"enabled"`
}

type SignalingConfig struct {
	Addr         string        `mapstructure:"addr"` // e.g. ":8080"
	Path         string        `mapstructure:"path"` // e.g. "/ws"
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

type SFUConfig struct {
	MaxPublishBitrate   int64 `mapstructure:"max_publish_bitrate"` // bps
	MaxSubscribeBitrate int64 `mapstructure:"max_subscribe_bitrate"`
	EnableRecorder      bool  `mapstructure:"enable_recorder"`
}

type WebRTCConfig struct {
	ICEServers      []string `mapstructure:"ice_servers"` // e.g. ["stun:stun.l.google.com:19302"]
	NAT1To1IPs      []string `mapstructure:"nat_1to1_ips"`
	PreferredCodecs []string `mapstructure:"preferred_codecs"` // ["vp8","opus"]
	MTU             int      `mapstructure:"mtu"`
}

type Config struct {
	Log       LogConfig       `mapstructure:"log"`
	Metrics   MetricsConfig   `mapstructure:"metrics"`
	HTTP      HTTPConfig      `mapstructure:"http"`
	WebRTC    WebRTCConfig    `mapstructure:"webrtc"`
	Tracing   TracingConfig   `mapstructure:"tracing"`
	Signaling SignalingConfig `mapstructure:"signaling"`
	SFU       SFUConfig       `mapstructure:"sfu"`
}

func DefaultConfig() Config {
	return Config{
		Log:     LogConfig{Level: "info", Format: LogFormatText},
		Metrics: MetricsConfig{Addr: ":2112"},
		HTTP:    HTTPConfig{Addr: ":8080"},
		Tracing: TracingConfig{
			Enabled: false, ServiceName: "ion", OTLPEndpoint: "", SampleRatio: 0.0,
		},
		Signaling: SignalingConfig{
			Addr: ":8080", Path: "/ws",
			ReadTimeout: DefaultSignalingTimeout, WriteTimeout: DefaultSignalingTimeout,
		},
		SFU: SFUConfig{
			MaxPublishBitrate: DefaultMaxPublishBitrate, MaxSubscribeBitrate: DefaultMaxSubscribeBitrate,
			EnableRecorder: false,
		},
		WebRTC: WebRTCConfig{
			ICEServers: []string{"stun:stun.l.google.com:19302"},
			NAT1To1IPs: nil, PreferredCodecs: []string{"vp8", "opus"},
			MTU: DefaultWebRTCMTU,
		},
	}
}

func RegisterFlags(fs *pflag.FlagSet) {
	def := DefaultConfig()

	// config file
	fs.String("config", "", "Path to config file (TOML/YAML/JSON)")

	// logging
	fs.String("log.level", def.Log.Level, "Log level (debug|info|warn|error)")
	fs.String("log.format", string(def.Log.Format), "Log format (text|json)")

	// metrics
	fs.String("metrics.addr", def.Metrics.Addr, "Prometheus metrics bind address (host:port or :port)")

	// http server
	fs.String("http.addr", def.HTTP.Addr, "HTTP server bind address (host:port or :port)")

	// tracing
	fs.Bool("tracing.enabled", def.Tracing.Enabled, "Enable OpenTelemetry tracing")
	fs.String("tracing.service_name", def.Tracing.ServiceName, "Tracing service name")
	fs.String("tracing.otlp_endpoint", def.Tracing.OTLPEndpoint, "OTLP exporter endpoint (e.g. host:4317)")
	fs.Float64("tracing.sample_ratio", def.Tracing.SampleRatio, "Tracing sampler ratio in [0.0,1.0]")

	// signaling
	fs.String("signaling.addr", def.Signaling.Addr, "Signaling server bind address (host:port or :port)")
	fs.String("signaling.path", def.Signaling.Path, "WebSocket path for signaling (e.g. /ws)")
	fs.Duration("signaling.read_timeout", def.Signaling.ReadTimeout, "Signaling HTTP read timeout")
	fs.Duration("signaling.write_timeout", def.Signaling.WriteTimeout, "Signaling HTTP write timeout")

	// -- sfu
	fs.Int64("sfu.max_publish_bitrate", def.SFU.MaxPublishBitrate, "Max allowed publish bitrate (bps)")
	fs.Int64("sfu.max_subscribe_bitrate", def.SFU.MaxSubscribeBitrate, "Max allowed subscribe bitrate (bps)")
	fs.Bool("sfu.enable_recorder", def.SFU.EnableRecorder, "Enable server-side recording")

	// -- webrtc
	fs.StringSlice("webrtc.ice_servers", def.WebRTC.ICEServers, "ICE servers (e.g. stun:stun.l.google.com:19302)")
	fs.StringSlice("webrtc.nat_1to1_ips", def.WebRTC.NAT1To1IPs, "NAT 1:1 IPs advertised via ICE (external IPs)")
	fs.StringSlice("webrtc.preferred_codecs", def.WebRTC.PreferredCodecs, "Preferred codecs (e.g. vp8, h264, opus)")
	fs.Int("webrtc.mtu", def.WebRTC.MTU, "Max Datagram MTU for RTP/DTLS (bytes)")
}

// Load returns config struct for ION.
func Load(fs *pflag.FlagSet) (Config, error) {
	cfg := DefaultConfig()
	vp := viper.New()

	// Defaults
	vp.SetDefault("log.level", cfg.Log.Level)
	vp.SetDefault("log.format", cfg.Log.Format)

	vp.SetDefault("metrics.addr", cfg.Metrics.Addr)

	vp.SetDefault("http.addr", cfg.HTTP.Addr)

	vp.SetDefault("tracing.enabled", cfg.Tracing.Enabled)
	vp.SetDefault("tracing.service_name", cfg.Tracing.ServiceName)
	vp.SetDefault("tracing.otlp_endpoint", cfg.Tracing.OTLPEndpoint)
	vp.SetDefault("tracing.sample_ratio", cfg.Tracing.SampleRatio)

	vp.SetDefault("signaling.addr", cfg.Signaling.Addr)
	vp.SetDefault("signaling.path", cfg.Signaling.Path)
	vp.SetDefault("signaling.read_timeout", cfg.Signaling.ReadTimeout)
	vp.SetDefault("signaling.write_timeout", cfg.Signaling.WriteTimeout)

	vp.SetDefault("sfu.max_publish_bitrate", cfg.SFU.MaxPublishBitrate)
	vp.SetDefault("sfu.max_subscribe_bitrate", cfg.SFU.MaxSubscribeBitrate)
	vp.SetDefault("sfu.enable_recorder", cfg.SFU.EnableRecorder)

	vp.SetDefault("webrtc.ice_servers", cfg.WebRTC.ICEServers)
	vp.SetDefault("webrtc.nat_1to1_ips", cfg.WebRTC.NAT1To1IPs)
	vp.SetDefault("webrtc.preferred_codecs", cfg.WebRTC.PreferredCodecs)
	vp.SetDefault("webrtc.mtu", cfg.WebRTC.MTU)

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
	if f := fs.Lookup("config"); f != nil {
		cfgPath = f.Value.String()
	}
	if cfgPath != "" {
		vp.SetConfigFile(cfgPath)
		if err := vp.ReadInConfig(); err != nil {
			// since user explicitly provided a path, any read error should fail the load
			return Config{}, fmt.Errorf("failed to read config %q: %w", cfgPath, err)
		}
	}

	if err := vp.UnmarshalExact(&cfg); err != nil {
		return Config{}, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return cfg, nil
}
