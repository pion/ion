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
	TestFlagAddr string = ":50500"
)

/********** helpers **********/

func resetViperAndEnv(t *testing.T) {
	t.Helper()
	viper.Reset()
	// reset env used by the loader
	_ = os.Unsetenv("ION_LOG_LEVEL")
	_ = os.Unsetenv("ION_LOG_FORMAT")
	_ = os.Unsetenv("ION_HTTP_ADDR")
	_ = os.Unsetenv("ION_METRICS_ADDR")
}

func newFS(t *testing.T, args ...string) *pflag.FlagSet {
	t.Helper()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	// define only flags your loader expects
	fs.String("config", "", "config file path")
	fs.String("log.level", "", "log level")
	fs.String("log.format", "", "log format")
	fs.String("http.addr", "", "http address")
	fs.String("metrics.addr", "", "metrics address")
	require.NoError(t, fs.Parse(args))

	return fs
}

func writeTempConfigWithHTTPAddr(t *testing.T, addr string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "ion*.toml")
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	_, err = fmt.Fprintf(f, "[http]\naddr = '%s'\n", addr)
	require.NoError(t, err)
	require.NoError(t, f.Sync())

	return f.Name()
}

/********** tests **********/

func TestDefaults(t *testing.T) {
	resetViperAndEnv(t)

	fs := newFS(t /* no args */)
	cfg, err := config.Load(fs)
	require.NoError(t, err)

	require.Equal(t, config.DefaultHTTPAddr, cfg.HTTP.Addr)
	require.Equal(t, config.DefaultLogLevel, cfg.Log.Level)
	require.Equal(t, config.DefaultLogFormat, cfg.Log.Format)
	require.Equal(t, config.DefaultMetricsAddr, cfg.Metrics.Addr)
}

func TestPriority_FileOverridesDefault(t *testing.T) {
	resetViperAndEnv(t)

	path := writeTempConfigWithHTTPAddr(t, testFileAddr)

	fs := newFS(t, "--config", path)

	cfg, err := config.Load(fs)
	require.NoError(t, err)
	require.Equal(t, testFileAddr, cfg.HTTP.Addr, "file should override default")
}

func TestPriority_EnvOverridesFile(t *testing.T) {
	resetViperAndEnv(t)

	path := writeTempConfigWithHTTPAddr(t, testFileAddr)
	t.Setenv("ION_HTTP_ADDR", testEnvAddr)

	fs := newFS(t, "--config", path)

	cfg, err := config.Load(fs)
	require.NoError(t, err)
	require.Equal(t, testEnvAddr, cfg.HTTP.Addr, "env should override file")
}

func TestPriority_FlagOverridesEnvAndFile(t *testing.T) {
	resetViperAndEnv(t)

	path := writeTempConfigWithHTTPAddr(t, testFileAddr)
	t.Setenv("ION_HTTP_ADDR", testEnvAddr)

	// Supply --config, env, and --http.addr; flags win
	fs := newFS(t, "--config", path, "--http.addr", TestFlagAddr)

	cfg, err := config.Load(fs)
	require.NoError(t, err)
	require.Equal(t, TestFlagAddr, cfg.HTTP.Addr, "flag should override env+file")
}

func TestInvalidConfigFileKey(t *testing.T) {
	resetViperAndEnv(t)

	// Create a bad config TOML with an unknown key "xxx"
	f, err := os.CreateTemp(t.TempDir(), "bad*.toml")
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	_, err = f.WriteString("[http]\nxxx = ':8080'\n")
	require.NoError(t, err)
	require.NoError(t, f.Sync())

	fs := newFS(t, "--config", f.Name())

	_, err = config.Load(fs)
	require.Error(t, err, "expected error for unknown key 'xxx'")
}
