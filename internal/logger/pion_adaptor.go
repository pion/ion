// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package logger

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	pionLogging "github.com/pion/logging"
)

const (
	LevelTrace = slog.Level(-8)
)

type PionFields map[string]any

type attrFields struct {
	attrs []slog.Attr
	mu    sync.RWMutex
}

type PionAdaptorFactory struct {
	ionLoggerFactory *LoggerFactory
	ctx              context.Context //nolint:containedctx // context kept only for logging
	attrs            *attrFields
}

// NewLogger implements the interface for pion logging library
// so that this PionAdaptorFactory can be passed into
// webrtc api.
func (f *PionAdaptorFactory) NewLogger(scope string) pionLogging.LeveledLogger {
	newCtx := f.ionLoggerFactory.BuildLoggerForCtx(f.ctx, scope)
	base := f.ionLoggerFactory.FromCtx(newCtx)
	logger := slog.New(&dynamicAttrsHandler{next: base.Handler(), attrFields: f.attrs})

	return &PionAdaptorLogger{
		logger: logger,
		ctx:    f.ctx,
	}
}

// PionAdaptorLogger is wrapper around slog logger that
// implements LeveledLogger interface.
type PionAdaptorLogger struct {
	logger *slog.Logger
	ctx    context.Context //nolint:containedctx // context kept only for logging
}

// Wrapper functions for pion logging interface.

func (adaptor *PionAdaptorLogger) Trace(msg string) {
	adaptor.logger.Log(adaptor.ctx, LevelTrace, msg)
}

func (adaptor *PionAdaptorLogger) Tracef(format string, args ...any) {
	adaptor.logger.Log(adaptor.ctx, LevelTrace, fmt.Sprintf(format, args...))
}

func (adaptor *PionAdaptorLogger) Debug(msg string) {
	adaptor.logger.DebugContext(adaptor.ctx, msg)
}

func (adaptor *PionAdaptorLogger) Debugf(format string, args ...any) {
	adaptor.logger.DebugContext(adaptor.ctx, fmt.Sprintf(format, args...))
}

func (adaptor *PionAdaptorLogger) Info(msg string) {
	adaptor.logger.InfoContext(adaptor.ctx, msg)
}

func (adaptor *PionAdaptorLogger) Infof(format string, args ...any) {
	adaptor.logger.InfoContext(adaptor.ctx, fmt.Sprintf(format, args...))
}

func (adaptor *PionAdaptorLogger) Warn(msg string) {
	adaptor.logger.InfoContext(adaptor.ctx, msg)
}

func (adaptor *PionAdaptorLogger) Warnf(format string, args ...any) {
	adaptor.logger.InfoContext(adaptor.ctx, fmt.Sprintf(format, args...))
}

func (adaptor *PionAdaptorLogger) Error(msg string) {
	adaptor.logger.ErrorContext(adaptor.ctx, msg)
}

func (adaptor *PionAdaptorLogger) Errorf(format string, args ...any) {
	adaptor.logger.ErrorContext(adaptor.ctx, fmt.Sprintf(format, args...))
}

// WithFields a chainable wrapper to decorate a factory with extra attributes.
func (f *PionAdaptorFactory) WithFields(kv PionFields) *PionAdaptorFactory {
	f.attrs.Add(kv)

	return f
}

// NewPionAdaptor generates a PionAdaptorFactory that can be passed
// into a webrtc api. The webrtc api will generate logger using
// this factory with context ctx.
func (f *LoggerFactory) NewPionAdaptor(ctx context.Context) *PionAdaptorFactory {
	factory := PionAdaptorFactory{
		ionLoggerFactory: f,
		ctx:              ctx,
		attrs:            &attrFields{},
	}

	return &factory
}

func (b *attrFields) Snapshot() []slog.Attr {
	b.mu.RLock()
	defer b.mu.RUnlock()
	// return a copy to avoid aliasing
	out := make([]slog.Attr, len(b.attrs))
	copy(out, b.attrs)

	return out
}

// Add addes a new.
func (b *attrFields) Add(kv PionFields) {
	b.mu.Lock()
	for k, v := range kv {
		b.attrs = append(b.attrs, slog.Any(k, v))
	}
	b.mu.Unlock()
}

// dynamicAttrsHandler wraps a handler and appends attrs on every record.
type dynamicAttrsHandler struct {
	next       slog.Handler
	attrFields *attrFields
}

func (h *dynamicAttrsHandler) Enabled(ctx context.Context, lvl slog.Level) bool {
	return h.next.Enabled(ctx, lvl)
}

func (h *dynamicAttrsHandler) Handle(ctx context.Context, rec slog.Record) error {
	if h.attrFields != nil {
		for _, a := range h.attrFields.Snapshot() {
			rec.AddAttrs(a)
		}
	}

	return h.next.Handle(ctx, rec)
}

func (h *dynamicAttrsHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &dynamicAttrsHandler{next: h.next.WithAttrs(attrs), attrFields: h.attrFields}
}

func (h *dynamicAttrsHandler) WithGroup(name string) slog.Handler {
	return &dynamicAttrsHandler{next: h.next.WithGroup(name), attrFields: h.attrFields}
}
