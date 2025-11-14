// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package config

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/pion/ion/v2/internal/utils"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

const (
	testFileAddr string = ":30300"
	testEnvAddr  string = ":40400"
	testFlagAddr string = ":50500"
)

func resetViperAndEnv(t *testing.T) {
	t.Helper()
	viper.Reset()
	// reset env used by the loader
	_ = os.Unsetenv("ION_TELEMETRY_LOGS_LEVEL")
	_ = os.Unsetenv("ION_TELEMETRY_LOGS_FORMAT")
	_ = os.Unsetenv("ION_TELEMETRY_METRICS_PROMETHEUS_ADDR")
	_ = os.Unsetenv("ION_TELEMETRY_METRICS_PROMETHEUS_ENABLED")
	_ = os.Unsetenv("ION_TELEMETRY_METRICS_OTLP_ENABLED")
	_ = os.Unsetenv("ION_TELEMETRY_METRICS_OTLP_ENDPOINT")
	_ = os.Unsetenv("ION_TELEMETRY_TRACES_ENABLED")
	_ = os.Unsetenv("ION_TELEMETRY_TRACES_SERVICE_NAME")
	_ = os.Unsetenv("ION_TELEMETRY_TRACES_OTLP_ENDPOINT")
	_ = os.Unsetenv("ION_TELEMETRY_TRACES_SAMPLE_RATIO")
}

func newFS(t *testing.T, args ...string) *pflag.FlagSet {
	t.Helper()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterFlags(fs)
	require.NoError(t, fs.Parse(args))

	return fs
}

func writeTempConfigWithPromAddr(t *testing.T, addr string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "ion*.toml")
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	_, err = fmt.Fprintf(f, "[telemetry.metrics.prometheus]\naddr = '%s'\n", addr)
	require.NoError(t, err)
	require.NoError(t, f.Sync())

	return f.Name()
}

func TestDefaults(t *testing.T) {
	resetViperAndEnv(t)

	fs := newFS(t /* no args */)
	cfg, err := Load(fs)
	require.NoError(t, err)

	require.Equal(t, DefaultLogLevel, cfg.Telemetry.Logs.Level)
	require.Equal(t, DefaultLogFormat, cfg.Telemetry.Logs.Format)
	require.Equal(t, DefaultPrometheusAddr, cfg.Telemetry.Metrics.Prometheus.Addr)
}

func TestLoadICEErr(t *testing.T) {
	resetViperAndEnv(t)

	fs := newFS(t /* no args */)
	err := fs.Parse([]string{
		"--ice.turn.enabled",
		"--ice.turn.port_range_min=0",
	})
	require.NoError(t, err)
	_, err = Load(fs)
	require.Error(t, err)
}

func TestLoadTelemetryErr(t *testing.T) {
	resetViperAndEnv(t)

	fs := newFS(t /* no args */)
	err := fs.Parse([]string{
		"--telemetry.logs.level=invalid",
		"--ice.turn.port_range_min=0",
	})
	require.NoError(t, err)
	_, err = Load(fs)
	require.Error(t, err)
}

func TestPriority_FileOverridesDefault(t *testing.T) {
	resetViperAndEnv(t)

	path := writeTempConfigWithPromAddr(t, testFileAddr)
	fs := newFS(t, "--config", path)

	cfg, err := Load(fs)
	require.NoError(t, err)
	require.Equal(t, testFileAddr, cfg.Telemetry.Metrics.Prometheus.Addr, "file should override default")
}

func TestPriority_EnvOverridesFile(t *testing.T) {
	resetViperAndEnv(t)

	path := writeTempConfigWithPromAddr(t, testFileAddr)
	t.Setenv("ION_TELEMETRY_METRICS_PROMETHEUS_ADDR", testEnvAddr)

	fs := newFS(t, "--config", path)

	cfg, err := Load(fs)
	require.NoError(t, err)
	require.Equal(t, testEnvAddr, cfg.Telemetry.Metrics.Prometheus.Addr, "env should override file")
}

func TestPriority_FlagOverridesEnvAndFile(t *testing.T) {
	resetViperAndEnv(t)

	path := writeTempConfigWithPromAddr(t, testFileAddr)
	t.Setenv("ION_TELEMETRY_METRICS_PROMETHEUS_ADDR", testEnvAddr)

	// Supply --config, env, and flag; flags win
	fs := newFS(t, "--config", path, "--telemetry.metrics.prometheus.addr", testFlagAddr)

	cfg, err := Load(fs)
	require.NoError(t, err)
	require.Equal(t, testFlagAddr, cfg.Telemetry.Metrics.Prometheus.Addr, "flag should override env+file")
}

func TestInvalidConfigFileKey(t *testing.T) {
	resetViperAndEnv(t)

	// Create a bad config TOML with an unknown key "xxx" under a valid section
	f, err := os.CreateTemp(t.TempDir(), "bad*.toml")
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	_, err = f.WriteString("[telemetry.metrics.prometheus]\nxxx = ':8080'\n")
	require.NoError(t, err)
	require.NoError(t, f.Sync())

	fs := newFS(t, "--config", f.Name())

	_, err = Load(fs)
	require.Error(t, err, "expected error for unknown key 'xxx'")
}

func TestRegisterFlags(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterFlags(fs)

	def := DefaultConfig()

	tests := []struct {
		name     string
		defValue string
		usage    string
	}{
		{
			name:     "config",
			defValue: "",
			usage:    "Path to config file (TOML)",
		},
		{
			name:     "telemetry.logs.level",
			defValue: def.Telemetry.Logs.Level,
			usage:    "Log level (debug|info|warn|error)",
		},
		{
			name:     "telemetry.logs.format",
			defValue: string(def.Telemetry.Logs.Format),
			usage:    "Log format (text|json)",
		},
		{
			name:     "telemetry.metrics.prometheus.enabled",
			defValue: strconv.FormatBool(def.Telemetry.Metrics.Prometheus.Enabled),
			usage:    "Enable Prometheus metrics exporter (scrape endpoint)",
		},
		{
			name:     "telemetry.metrics.prometheus.addr",
			defValue: def.Telemetry.Metrics.Prometheus.Addr,
			usage:    "Prometheus metrics bind address (host:port or :port)",
		},
		{
			name:     "telemetry.metrics.otlp.enabled",
			defValue: strconv.FormatBool(def.Telemetry.Metrics.OTLP.Enabled),
			usage:    "Enable OTLP metrics exporter (push)",
		},
		{
			name:     "telemetry.metrics.otlp.endpoint",
			defValue: def.Telemetry.Metrics.OTLP.Endpoint,
			usage:    "OTLP metrics endpoint (e.g. host:4317)",
		},
		{
			name:     "telemetry.traces.otlp.enabled",
			defValue: strconv.FormatBool(def.Telemetry.Traces.OTLP.Enabled),
			usage:    "Enable OpenTelemetry tracing via OTLP",
		},
		{
			name:     "telemetry.traces.otlp.service_name",
			defValue: def.Telemetry.Traces.OTLP.ServiceName,
			usage:    "Tracing service name",
		},
		{
			name:     "telemetry.traces.otlp.endpoint",
			defValue: def.Telemetry.Traces.OTLP.Endpoint,
			usage:    "OTLP traces endpoint (e.g. host:4317)",
		},
		{
			name:     "telemetry.traces.otlp.sample_ratio",
			defValue: strconv.FormatFloat(def.Telemetry.Traces.OTLP.SampleRatio, 'f', -1, 64),
			usage:    "Tracing sampler ratio in [0.0,1.0]",
		},

		// ice.stun
		{
			name:     "ice.stun.enabled",
			defValue: strconv.FormatBool(def.ICE.STUN.Enabled),
			usage:    "Enable embedded STUN server",
		},
		{
			name:     "ice.stun.udp_endpoint",
			defValue: def.ICE.STUN.UDPEndpoint,
			usage:    "STUN UDP bind (host:port or :port)",
		},
		{
			name:     "ice.stun.tcp_endpoint",
			defValue: def.ICE.STUN.TCPEndpoint,
			usage:    "STUN TCP bind (host:port or :port)",
		},

		// ice.turn
		{
			name:     "ice.turn.enabled",
			defValue: strconv.FormatBool(def.ICE.TURN.Enabled),
			usage:    "Enable embedded TURN server",
		},
		{
			name:     "ice.turn.udp_endpoint",
			defValue: def.ICE.TURN.UDPEndpoint,
			usage:    "TURN UDP bind (host:port or :port)",
		},
		{
			name:     "ice.turn.tcp_endpoint",
			defValue: def.ICE.TURN.TCPEndpoint,
			usage:    "TURN TCP bind (host:port or :port)",
		},
		{
			name:     "ice.turn.public_ip",
			defValue: def.ICE.TURN.PublicIP,
			usage:    "Public IP return to TURN client",
		},
		{
			name:     "ice.turn.realm",
			defValue: def.ICE.TURN.Realm,
			usage:    "TURN realm",
		},
		{
			name:     "ice.turn.auth",
			defValue: def.ICE.TURN.Auth,
			usage:    "TURN auth mode (long-term|static)",
		},
		{
			name:     "ice.turn.user",
			defValue: def.ICE.TURN.User,
			usage:    "TURN static username (for long-term auth)",
		},
		{
			name:     "ice.turn.password",
			defValue: def.ICE.TURN.Password,
			usage:    "TURN static password (for long-term auth)",
		},
		{
			name:     "ice.turn.secret",
			defValue: def.ICE.TURN.Secret,
			usage:    "TURN shared secret (for time-limited creds)",
		},
		{
			name:     "ice.turn.port_range_min",
			defValue: strconv.FormatUint(uint64(def.ICE.TURN.PortRangeMin), 10),
			usage:    "TURN min port range",
		},
		{
			name:     "ice.turn.port_range_max",
			defValue: strconv.FormatUint(uint64(def.ICE.TURN.PortRangeMax), 10),
			usage:    "TURN max port range",
		},
		{
			name:     "ice.turn.address",
			defValue: def.ICE.TURN.Address,
			usage:    "TURN address",
		},

		// ice.turn.tls
		{
			name:     "ice.turn.tls.endpoint",
			defValue: def.ICE.TURN.TLS.Endpoint,
			usage:    "TURN TLS bind (host:port or :port)",
		},
		{
			name:     "ice.turn.tls.cert",
			defValue: def.ICE.TURN.TLS.Cert,
			usage:    "TURN TLS certificate file path",
		},
		{
			name:     "ice.turn.tls.key",
			defValue: def.ICE.TURN.TLS.Key,
			usage:    "TURN TLS private key file path",
		},
		{
			name:     "ice.turn.tls.version",
			defValue: def.ICE.TURN.TLS.Version,
			usage:    "TURN TLS version (TLS12|TLS13)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := fs.Lookup(tt.name)
			require.NotNil(t, f, "flag %q not registered", tt.name)
			require.Equal(t, tt.defValue, f.DefValue, "default mismatch for %q", tt.name)
			require.Equal(t, tt.usage, f.Usage, "usage mismatch for %q", tt.name)
		})
	}
}

func TestTelemetryConfigValidate(t *testing.T) {
	t.Helper()

	tests := []struct {
		err    error
		mutate func(cfg *TelemetryConfig)
		name   string
	}{
		{
			name: "valid config passes",
			mutate: func(cfg *TelemetryConfig) {
			},
			err: nil,
		},
		{
			name: "invalid log level",
			mutate: func(cfg *TelemetryConfig) {
				cfg.Logs.Level = "verbose"
			},
			err: errInvalidLogLevel,
		},
		{
			name: "invalid log format",
			mutate: func(cfg *TelemetryConfig) {
				cfg.Logs.Format = "xml"
			},
			err: errInvalidLogFormat,
		},
		{
			name: "traces OTLP empty service name",
			mutate: func(cfg *TelemetryConfig) {
				cfg.Traces.OTLP.Enabled = true
				cfg.Traces.OTLP.ServiceName = ""
			},
			err: errEmptyOTLPServiceName,
		},
		{
			name: "traces OTLP negative sample ratio",
			mutate: func(cfg *TelemetryConfig) {
				cfg.Traces.OTLP.Enabled = true
				cfg.Traces.OTLP.SampleRatio = -0.1
			},
			err: errInvalidOTLPSampleRatio,
		},
		{
			name: "metrics prometheus invalid endpoint",
			mutate: func(cfg *TelemetryConfig) {
				cfg.Metrics.Prometheus.Enabled = true
				cfg.Metrics.Prometheus.Addr = "not-a-valid-endpoint"
			},
			err: utils.ErrInvalidHostPort,
		},
		{
			name: "metrics OTLP invalid endpoint",
			mutate: func(cfg *TelemetryConfig) {
				cfg.Metrics.OTLP.Enabled = true
				cfg.Metrics.OTLP.Endpoint = "also-bad-endpoint"
			},
			err: utils.ErrInvalidHostPort,
		},
		{
			name: "traces OTLP invalid endpoint",
			mutate: func(cfg *TelemetryConfig) {
				cfg.Traces.OTLP.Enabled = true
				cfg.Traces.OTLP.Endpoint = "bad-endpoint"
				cfg.Traces.OTLP.ServiceName = "svc"
				cfg.Traces.OTLP.SampleRatio = 1.0
			},
			err: utils.ErrInvalidHostPort,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := DefaultConfig().Telemetry
			if testCase.mutate != nil {
				testCase.mutate(&cfg)
			}

			err := cfg.validate()

			switch {
			case testCase.err != nil:
				require.Error(t, err)
				require.ErrorIs(t, err, testCase.err)
			case testCase.name == "metrics prometheus invalid endpoint" ||
				testCase.name == "metrics OTLP invalid endpoint" ||
				testCase.name == "traces OTLP invalid endpoint":
				require.Error(t, err)
			default:
				require.NoError(t, err)
			}
		})
	}
}
