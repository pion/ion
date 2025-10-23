// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package logger

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/pion/ion/v2/internal/config"
	"github.com/stretchr/testify/require"
)

type SafeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *SafeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *SafeBuffer) Sync() error { return nil }

// Helper for tests:
func (s *SafeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *SafeBuffer) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Len()
}
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

func TestScopeLevelAndModuleAttr(t *testing.T) {
	var buf SafeBuffer

	opts := Options{
		DefaultLevel:  "info", // debug should be dropped unless overridden
		Format:        config.LogFormat("json"),
		DefaultWriter: config.WriterStdout, // ignored due to TestWriter
		TestWriter:    &buf,
		ScopeLevels: map[string]string{
			"sfu": "debug", // override for this scope only
		},
	}

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

	out := buf.String()

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
	buf := &SafeBuffer{}
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

// helper: build a ctxHandler wrapping a JSON handler that writes to buf.
func newCtxHandler(buf *SafeBuffer, scope string) *ctxHandler {
	base := slog.NewJSONHandler(buf, &slog.HandlerOptions{}) // deterministic JSON

	return &ctxHandler{
		next:  base,
		scope: scope,
	}
}

func TestCtxHandler_WithAttrs(t *testing.T) {
	var buf SafeBuffer
	h := newCtxHandler(&buf, "sfu")

	// Derive with static attrs
	h2 := h.WithAttrs([]slog.Attr{
		slog.String("role", "offerer"),
	})
	require.IsType(t, &ctxHandler{}, h2)
	derived, ok := h2.(*ctxHandler)
	require.True(t, ok, "expected *ctxHandler, got %T", h2)

	// Scope must be preserved
	require.Equal(t, "sfu", derived.scope)
	require.Equal(t, h.scope, derived.scope)

	// Log through derived handler
	logger := slog.New(derived)
	logger.Info("hello", slog.String("k", "v"))

	out := buf.String()

	// Scope (module) stays at top level
	require.Contains(t, out, `"module":"sfu"`, "module should remain at top level")

	// Static attributes from WithAttrs are present
	require.Contains(t, out, `"role":"offerer"`)
	require.Contains(t, out, `"k":"v"`)
	require.Contains(t, out, `"msg":"hello"`)
	require.Contains(t, out, `"level":"INFO"`)
}

func TestCtxHandler_WithGroup_PreservesScopeAndNestsAttrs(t *testing.T) {
	var buf SafeBuffer
	h := newCtxHandler(&buf, "auth")

	// Derive grouped handler
	hg := h.WithGroup("conn")
	require.IsType(t, &ctxHandler{}, hg)
	g, ok := hg.(*ctxHandler)
	require.True(t, ok, "expected *ctxHandler, got %T", hg)

	// Scope must be preserved
	require.Equal(t, "auth", g.scope)

	// Log grouped fields
	logger := slog.New(g)
	logger.Info("state-change",
		slog.String("state", "open"),
		slog.Int("retries", 0),
	)

	out := buf.String()

	// Scope (module) remains at top level
	require.Contains(t, out, `"module":"auth"`)

	// Grouped fields appear nested under "conn"
	require.Contains(t, out, `"conn":{`)
	require.Contains(t, out, `"state":"open"`)
	require.Contains(t, out, `"retries":0`)

	// Message/level present
	require.Contains(t, out, `"msg":"state-change"`)
	require.Contains(t, out, `"level":"INFO"`)

	// Sanity: ensure "state" only appears as grouped (not top-level leak)
	require.Equal(t, 1, strings.Count(out, `"state":"open"`))
}
