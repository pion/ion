// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package config_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/pion/ion/v2/internal/config"
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
	// define only flags your loader expects/that we use here
	fs.String("config", "", "config file path")
	fs.String("telemetry.logs.level", "", "log level")
	fs.String("telemetry.logs.format", "", "log format")
	fs.String("telemetry.metrics.prometheus.addr", "", "prometheus bind addr")
	// keep flags minimal; precedence is what we test
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
	cfg, err := config.Load(fs)
	require.NoError(t, err)

	require.Equal(t, config.DefaultLogLevel, cfg.Telemetry.Logs.Level)
	require.Equal(t, config.DefaultLogFormat, cfg.Telemetry.Logs.Format)
	require.Equal(t, config.DefaultPrometheusAddr, cfg.Telemetry.Metrics.Prometheus.Addr)
}

func TestPriority_FileOverridesDefault(t *testing.T) {
	resetViperAndEnv(t)

	path := writeTempConfigWithPromAddr(t, testFileAddr)
	fs := newFS(t, "--config", path)

	cfg, err := config.Load(fs)
	require.NoError(t, err)
	require.Equal(t, testFileAddr, cfg.Telemetry.Metrics.Prometheus.Addr, "file should override default")
}

func TestPriority_EnvOverridesFile(t *testing.T) {
	resetViperAndEnv(t)

	path := writeTempConfigWithPromAddr(t, testFileAddr)
	t.Setenv("ION_TELEMETRY_METRICS_PROMETHEUS_ADDR", testEnvAddr)

	fs := newFS(t, "--config", path)

	cfg, err := config.Load(fs)
	require.NoError(t, err)
	require.Equal(t, testEnvAddr, cfg.Telemetry.Metrics.Prometheus.Addr, "env should override file")
}

func TestPriority_FlagOverridesEnvAndFile(t *testing.T) {
	resetViperAndEnv(t)

	path := writeTempConfigWithPromAddr(t, testFileAddr)
	t.Setenv("ION_TELEMETRY_METRICS_PROMETHEUS_ADDR", testEnvAddr)

	// Supply --config, env, and flag; flags win
	fs := newFS(t, "--config", path, "--telemetry.metrics.prometheus.addr", testFlagAddr)

	cfg, err := config.Load(fs)
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

	_, err = config.Load(fs)
	require.Error(t, err, "expected error for unknown key 'xxx'")
}
