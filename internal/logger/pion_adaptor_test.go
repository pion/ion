// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js
// +build !js

package logger

import (
	"context"
	"log/slog"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pion/ion/v2/internal/config"
	pionLogging "github.com/pion/logging"
	"github.com/pion/webrtc/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestImplementsLeveledLogger(t *testing.T) {
	var _ pionLogging.LeveledLogger = (*PionAdaptorLogger)(nil)
}

func newBufferedAdaptor(t *testing.T, minLevel slog.Level) (*PionAdaptorLogger, *SafeBuffer) {
	t.Helper()
	var buf SafeBuffer
	h := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: minLevel})
	l := slog.New(h)

	return &PionAdaptorLogger{logger: l, ctx: context.Background()}, &buf
}

func testNoDebugLevel(t *testing.T) {
	t.Helper()
	logger, buf := newBufferedAdaptor(t, slog.LevelInfo) // drop debug & trace

	logger.Debug("this shouldn't be logged")
	assert.Equal(t, 0, buf.Len(), "Debug was logged when it shouldn't have been")

	logger.Debugf("this shouldn't be logged")
	assert.Equal(t, 0, buf.Len(), "Debug was logged when it shouldn't have been")
}

func testDebugLevel(t *testing.T) {
	t.Helper()
	logger, buf := newBufferedAdaptor(t, slog.LevelDebug)

	dbgMsg := "this is a debug message"
	logger.Debug(dbgMsg)
	assert.Containsf(t, buf.String(), dbgMsg, "Expected %q in %q", dbgMsg, buf.String())

	logger.Debugf("%s", dbgMsg) // nolint: govet
	assert.Containsf(t, buf.String(), dbgMsg, "Expected %q in %q", dbgMsg, buf.String())
}

func testWarnLevel(t *testing.T) {
	t.Helper()
	logger, buf := newBufferedAdaptor(t, slog.LevelInfo)

	warnMsg := "this is a warning message"
	logger.Warn(warnMsg)
	assert.Containsf(t, buf.String(), warnMsg, "Expected %q in %q", warnMsg, buf.String())

	logger.Warnf("%s", warnMsg) // nolint: govet
	assert.Containsf(t, buf.String(), warnMsg, "Expected %q in %q", warnMsg, buf.String())
}

func testErrorLevel(t *testing.T) {
	t.Helper()
	logger, buf := newBufferedAdaptor(t, slog.LevelError)

	errMsg := "this is an error message"
	logger.Error(errMsg)
	assert.Containsf(t, buf.String(), errMsg, "Expected %q in %q", errMsg, buf.String())

	logger.Errorf("%s", errMsg) // nolint: govet
	assert.Containsf(t, buf.String(), errMsg, "Expected %q in %q", errMsg, buf.String())
}

func testTraceLevel(t *testing.T) {
	t.Helper()
	logger, buf := newBufferedAdaptor(t, LevelTrace) // allow custom trace level

	traceMsg := "trace message"
	logger.Trace(traceMsg)
	assert.Containsf(t, buf.String(), traceMsg, "Expected %q in %q", traceMsg, buf.String())

	logger.Tracef("%s", traceMsg) // nolint: govet
	assert.Containsf(t, buf.String(), traceMsg, "Expected %q in %q", traceMsg, buf.String())
}

func testInfoLevel(t *testing.T) {
	t.Helper()
	logger, buf := newBufferedAdaptor(t, slog.LevelInfo)

	infoMsg := "info message"
	logger.Info(infoMsg)
	assert.Containsf(t, buf.String(), infoMsg, "Expected %q in %q", infoMsg, buf.String())

	logger.Infof("%s", infoMsg) // nolint: govet
	assert.Containsf(t, buf.String(), infoMsg, "Expected %q in %q", infoMsg, buf.String())
}

func testAllLevels(t *testing.T) {
	t.Helper()
	logger, buf := newBufferedAdaptor(t, LevelTrace)

	dbgMsg := "d"
	logger.Debug(dbgMsg)
	require.Contains(t, buf.String(), dbgMsg)

	infoMsg := "i"
	logger.Info(infoMsg)
	require.Contains(t, buf.String(), infoMsg)

	warnMsg := "w"
	logger.Warn(warnMsg)
	require.Contains(t, buf.String(), warnMsg)

	errMsg := "e"
	logger.Error(errMsg)
	require.Contains(t, buf.String(), errMsg)

	traceMsg := "t"
	logger.Trace(traceMsg)
	require.Contains(t, buf.String(), traceMsg)
}

func TestNoDebugLevel(t *testing.T) { testNoDebugLevel(t) }
func TestDebugLevel(t *testing.T)   { testDebugLevel(t) }
func TestWarnLevel(t *testing.T)    { testWarnLevel(t) }
func TestErrorLevel(t *testing.T)   { testErrorLevel(t) }
func TestTraceLevel(t *testing.T)   { testTraceLevel(t) }
func TestInfoLevel(t *testing.T)    { testInfoLevel(t) }
func TestAllLevels(t *testing.T)    { testAllLevels(t) }

func TestTwoPeers_DistinctLoggerFieldsSingleProcess(t *testing.T) {
	if runtime.GOARCH == "wasm" || runtime.GOOS == "js" {
		t.Skip("Pion logger factory not available on wasm")
	}
	var bufA, bufB SafeBuffer

	lfA, err := NewLoggerFactory(Options{
		DefaultLevel:  "debug",
		Format:        config.LogFormatJSON,
		DefaultWriter: config.WriterStdout,
		TestWriter:    &bufA,
	})
	require.NoError(t, err)

	lfB, err := NewLoggerFactory(Options{
		DefaultLevel:  "debug",
		Format:        config.LogFormatJSON,
		DefaultWriter: config.WriterStdout,
		TestWriter:    &bufB,
	})
	require.NoError(t, err)

	// Build two independent Pion adaptors
	ctx := context.Background()
	adpA := lfA.NewPionAdaptor(ctx).WithFields(PionFields{"room_id": "rA"})
	adpB := lfB.NewPionAdaptor(ctx).WithFields(PionFields{"room_id": "rB"})

	// Two SettingEngines, each with its own adaptor
	var seA, seB webrtc.SettingEngine
	seA.LoggerFactory = adpA
	seB.LoggerFactory = adpB

	apiA := webrtc.NewAPI(webrtc.WithSettingEngine(seA))
	apiB := webrtc.NewAPI(webrtc.WithSettingEngine(seB))

	pcA, err := apiA.NewPeerConnection(webrtc.Configuration{})
	require.NoError(t, err)

	pcB, err := apiB.NewPeerConnection(webrtc.Configuration{})
	require.NoError(t, err)

	_, _ = pcA.CreateDataChannel("dc", nil)

	// In-memory trickle ICE exchange
	ice := func(src, dst *webrtc.PeerConnection) {
		src.OnICECandidate(func(c *webrtc.ICECandidate) {
			if c == nil {
				return
			}
			_ = dst.AddICECandidate(c.ToJSON())
		})
	}
	ice(pcA, pcB)
	ice(pcB, pcA)

	// Offer/answer flow
	offer, err := pcA.CreateOffer(nil)
	require.NoError(t, err)
	require.NoError(t, pcA.SetLocalDescription(offer))

	require.NoError(t, pcB.SetRemoteDescription(*pcA.LocalDescription()))
	answer, err := pcB.CreateAnswer(nil)
	require.NoError(t, err)
	require.NoError(t, pcB.SetLocalDescription(answer))
	require.NoError(t, pcA.SetRemoteDescription(*pcB.LocalDescription()))

	// Should have room_id in the attribute
	time.Sleep(100 * time.Millisecond)
	logsA := bufA.String()
	logsB := bufB.String()
	require.Contains(t, logsA, `"room_id":"rA"`)
	require.Contains(t, logsB, `"room_id":"rB"`)

	// Now add different fields per "process"/peer
	adpA.WithFields(map[string]any{"peer_id": "pA", "role": "offerer"})
	adpB.WithFields(map[string]any{"peer_id": "pB", "role": "answerer"})

	require.NoError(t, pcA.Close(), "pcA.Close should not fail")
	require.NoError(t, pcB.Close(), "pcB.Close should not fail")

	time.Sleep(100 * time.Millisecond)

	logsA = bufA.String()
	logsB = bufB.String()

	// Easy, focused assertions
	require.Contains(t, logsA, `"peer_id":"pA"`)
	require.Contains(t, logsA, `"role":"offerer"`)
	require.NotContains(t, logsA, `"peer_id":"pB"`)

	require.Contains(t, logsB, `"peer_id":"pB"`)
	require.Contains(t, logsB, `"role":"answerer"`)
	require.NotContains(t, logsB, `"peer_id":"pA"`)
}

// helper to build a dynamicAttrsHandler with a JSON next handler writing to buf.
func newDynamicHandler(buf *SafeBuffer) *dynamicAttrsHandler {
	base := slog.NewJSONHandler(buf, &slog.HandlerOptions{}) // deterministic JSON

	return &dynamicAttrsHandler{
		next:       base,
		attrFields: &attrFields{},
	}
}

func TestDynamicAttrsHandler_WithAttrs(t *testing.T) {
	var buf SafeBuffer
	dh := newDynamicHandler(&buf)

	// Call WithAttrs to add a static attribute
	h2 := dh.WithAttrs([]slog.Attr{slog.String("scope", "sfu")})
	require.IsType(t, &dynamicAttrsHandler{}, h2)
	dh2, ok := h2.(*dynamicAttrsHandler)
	require.True(t, ok, "expected *dynamicAttrsHandler, got %T", h2)

	logger := slog.New(dh2)
	logger.Info("hello", slog.String("k", "v"))

	out := buf.String()

	require.Contains(t, out, `"scope":"sfu"`, "static attr from WithAttrs should be present")

	require.Contains(t, out, `"msg":"hello"`)
	require.Contains(t, out, `"level":"INFO"`)
}

func TestDynamicAttrsHandler_WithGroup(t *testing.T) {
	var buf SafeBuffer
	dh := newDynamicHandler(&buf)

	hGrouped := dh.WithGroup("conn")
	require.IsType(t, &dynamicAttrsHandler{}, hGrouped)
	dhGrouped, ok := hGrouped.(*dynamicAttrsHandler)
	require.True(t, ok, "expected *ctxHandler, got %T", hGrouped)

	logger := slog.New(dhGrouped)

	// Emit grouped attributes.
	logger.Info("state-change",
		slog.String("state", "open"),
		slog.Int("retries", 0),
	)

	out := buf.String()

	// Grouped fields appear nested under "conn".
	// JSON shape from slog's JSON handler should be: ..."conn":{"state":"open","retries":0}...
	require.Contains(t, out, `"conn":{`)
	require.Contains(t, out, `"state":"open"`)
	require.Contains(t, out, `"retries":0`)

	// And still includes message/level.
	require.Contains(t, out, `"msg":"state-change"`)
	require.Contains(t, out, `"level":"INFO"`)

	// Quick structure sanity: grouped keys should not leak at top level.
	// (Best-effort: check that "state" key isn't top-level by looking for `"state":"open"` outside group start.
	// Since we already asserted group presence, ensure there's exactly one occurrence.)
	require.Equal(t, 1, strings.Count(out, `"state":"open"`))
}
