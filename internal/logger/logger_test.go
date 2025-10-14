// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package logger

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"runtime"
	"testing"

	"github.com/pion/ion/v2/internal/config"
	"github.com/stretchr/testify/require"
)

func TestBuildWriteSyncer(t *testing.T) {
	t.Run("stdout", func(t *testing.T) {
		ws, err := BuildWriteSyncer(config.WriterStdout)
		require.NoError(t, err)
		require.NotNil(t, ws)
	})

	t.Run("stderr", func(t *testing.T) {
		ws, err := BuildWriteSyncer(config.WriterStderr)
		require.NoError(t, err)
		require.NotNil(t, ws)
	})

	t.Run("invalid", func(t *testing.T) {
		_, err := BuildWriteSyncer(config.WriterType("not-a-writer"))
		require.Error(t, err)
	})
}

func TestBuildEncoder(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		enc, err := BuildEncoder(config.LogFormat("json"))
		require.NoError(t, err)
		require.NotNil(t, enc)
	})

	t.Run("text", func(t *testing.T) {
		enc, err := BuildEncoder(config.LogFormat("text"))
		require.NoError(t, err)
		require.NotNil(t, enc)
	})

	t.Run("invalid", func(t *testing.T) {
		_, err := BuildEncoder(config.LogFormat("xml"))
		require.Error(t, err)
	})
}

func TestParseZapLevel(t *testing.T) {
	cases := map[string]int8{
		"debug":    -1,
		"info":     0,
		"":         0,
		"warn":     1,
		"warning":  1,
		"error":    2,
		"garbage!": 0,
	}
	for in, want := range cases {
		lvl := ParseZapLevel(in)
		require.Equal(t, want, int8(lvl), "input=%q", in)
	}
}

func TestNewLoggerFactory(t *testing.T) {
	opts := Options{
		DefaultLevel:  "info",
		Format:        config.LogFormat("json"),
		ScopeLevels:   map[string]string{},
		DefaultWriter: config.WriterStdout,
	}
	f, err := NewLoggerFactory(opts)
	require.NoError(t, err)
	require.NotNil(t, f)
	require.NotNil(t, f.rootLogger)
}

// NOTE: Build the factory *inside* this capture so zap binds to the pipe.
func captureStdout(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	b, _ := io.ReadAll(r)
	_ = r.Close()

	return string(b)
}

func TestScopeLevelAndModuleAttr(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skip("stdout/stderr capture not supported under js/wasm; skip")
	}
	opts := Options{
		DefaultLevel:  "info", // debug should be dropped unless overridden
		Format:        config.LogFormat("json"),
		DefaultWriter: config.WriterStdout,
		ScopeLevels: map[string]string{
			"sfu": "debug", // override for this scope only
		},
	}

	out := captureStdout(func() {
		f, err := NewLoggerFactory(opts)
		require.NoError(t, err)

		// Scope with debug level enabled.
		ctx := f.BuildLoggerForCtx(context.Background(), "sfu")
		l1 := f.FromCtx(ctx)
		l1.Debug("sfu-debug", slog.String("k", "v"))

		// Scope without override should drop debug at default info level.
		ctx2 := f.BuildLoggerForCtx(context.Background(), "other")
		l2 := f.FromCtx(ctx2)
		l2.Debug("drop-me", slog.String("x", "y"))

		// Emit an info from "other" to ensure we get at least one record from it.
		l2.Info("visible-info")
	})

	// Should include the debug message and module tag for "sfu".
	require.Contains(t, out, `"msg":"sfu-debug"`, "expected debug message for sfu")
	require.Contains(t, out, `"module":"sfu"`, "expected module attribute for sfu")

	// "drop-me" should not appear because default scope is info.
	require.NotContains(t, out, `"msg":"drop-me"`, "did not expect debug message for default scope")

	// Sanity: the info from "other" should appear and carry module=other.
	require.Contains(t, out, `"msg":"visible-info"`, "expected info message for other scope")
	require.Contains(t, out, `"module":"other"`, "expected module attribute for other")
}

func TestHandlerSingletonPerScope(t *testing.T) {
	f, err := NewLoggerFactory(Options{
		DefaultLevel:  "info",
		Format:        config.LogFormat("json"),
		DefaultWriter: config.WriterStdout,
	})
	require.NoError(t, err)

	h1 := f.newHandler("auth")
	h2 := f.newHandler("auth")
	h3 := f.newHandler("sfu")

	require.Same(t, h1, h2, "expected same handler instance for identical scope")
	require.NotSame(t, h1, h3, "expected different handler instances for different scopes")
}

func TestWithContextAndFromCtx(t *testing.T) {
	factory, err := NewLoggerFactory(Options{
		DefaultLevel:  "info",
		Format:        config.LogFormat("json"),
		DefaultWriter: config.WriterStdout,
	})
	require.NoError(t, err)

	// Put a custom logger into context and ensure FromCtx returns it.
	buf := &bytes.Buffer{}
	custom := slog.New(slog.NewTextHandler(buf, nil))
	ctx := WithContext(context.Background(), custom)

	got := factory.FromCtx(ctx)
	require.Same(t, custom, got, "FromCtx should return logger stored in context")

	// When nothing in context, FromCtx should return factory root (non-nil).
	got2 := factory.FromCtx(context.Background())
	require.NotNil(t, got2)
}

func TestRetriveLoggerfromCtx_Default(t *testing.T) {
	l := retriveLoggerfromCtx(context.Background())
	require.Nil(t, l, "expected nil when context has no logger")
}
