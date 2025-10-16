// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package logger provides contextual log features for Ion using slog interface
// and zap backend.
package logger

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/pion/ion/v2/internal/config"
	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
	"go.uber.org/zap/zapcore"
)

type ctxKey struct{}

type Options struct {
	DefaultLevel  string
	Format        config.LogFormat
	ScopeLevels   map[string]string
	DefaultWriter config.WriterType
}

type LoggerFactory struct {
	ws           zapcore.WriteSyncer
	encoder      zapcore.Encoder
	defaultLevel zap.AtomicLevel
	scopeLevels  map[string]zap.AtomicLevel
	cache        map[string]slog.Handler
	rootLogger   *slog.Logger
	mu           sync.RWMutex
}

// BuildWriteSyncer parses and build a Zap WriteSyncer.
func BuildWriteSyncer(writer config.WriterType) (zapcore.WriteSyncer, error) {
	switch strings.ToLower(string(writer)) {
	case string(config.WriterStderr):
		return zapcore.AddSync(os.Stderr), nil
	case string(config.WriterStdout):
		return zapcore.AddSync(os.Stdout), nil
	default:
		return nil, config.ErrInvalidWriterType
	}
}

// BuildEncoder parses and builds a Zap encoder.
func BuildEncoder(format config.LogFormat) (zapcore.Encoder, error) {
	switch strings.ToLower(string(format)) {
	case "text":
		return zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()), nil
	case "json", "":
		return zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), nil
	default:
		return nil, config.ErrInvalidFormatType
	}
}

// ParseZapLevel parses level from string to zapcore.Levels.
func ParseZapLevel(level string) zapcore.Level {
	switch strings.ToLower(level) {
	case "debug":
		return zapcore.DebugLevel
	case "info", "":
		return zapcore.InfoLevel
	case "warn", "warning":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}

// NewLoggerFactory creates a new LoggerFactory.
func NewLoggerFactory(opts Options) (*LoggerFactory, error) {
	ws, err := BuildWriteSyncer(opts.DefaultWriter)
	if err != nil {
		return nil, err
	}

	encoder, err := BuildEncoder(opts.Format)
	if err != nil {
		return nil, err
	}

	defaultLevel := zap.NewAtomicLevelAt(ParseZapLevel(opts.DefaultLevel))
	factory := &LoggerFactory{
		ws:           ws,
		encoder:      encoder,
		defaultLevel: defaultLevel,
		scopeLevels:  make(map[string]zap.AtomicLevel),
		cache:        make(map[string]slog.Handler),
	}

	for scope, level := range opts.ScopeLevels {
		factory.scopeLevels[scope] = zap.NewAtomicLevelAt(ParseZapLevel(level))
	}

	rootCore := zapcore.NewCore(encoder, ws, defaultLevel)
	rootZap := zap.New(rootCore, zap.AddCaller())
	rootBase := zapslog.NewHandler(rootZap.Core())
	factory.rootLogger = slog.New(&ctxHandler{next: rootBase})

	return factory, nil
}

// WithContext stores a logger in context and return copy of the context.
func WithContext(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

// BuildLoggerForCtx creates a logger and bind it with
// ctx appending with scope key value pair.
func (f *LoggerFactory) BuildLoggerForCtx(ctx context.Context, scope string) context.Context {
	h := f.newHandler(scope)
	h = &ctxHandler{next: h, scope: scope}

	return WithContext(ctx, slog.New(h))
}

// FromCtx returns the logger stored in ctx or the factory root logger.
func (f *LoggerFactory) FromCtx(ctx context.Context) *slog.Logger {
	if lg := retriveLoggerfromCtx(ctx); lg != nil {
		return lg
	}

	return f.rootLogger
}

// RetriveLoggerfromCtx retrieves the logger associated with ctx
// or returns nil.
func retriveLoggerfromCtx(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok && l != nil {
		return l
	}

	return nil
}

// NewHandler returns a singleton slog.Handler per scope.
// The defult log level will be used unless specified in the config.
func (f *LoggerFactory) newHandler(scope string) slog.Handler {
	f.mu.RLock()
	if handler, ok := f.cache[scope]; ok {
		f.mu.RUnlock()

		return handler
	}
	f.mu.RUnlock()

	level := f.defaultLevel
	f.mu.RLock()
	if sl, ok := f.scopeLevels[scope]; ok {
		level = sl
	}
	f.mu.RUnlock()

	core := zapcore.NewCore(f.encoder, f.ws, level)
	zl := zap.New(core, zap.AddCaller())

	handler := zapslog.NewHandler(zl.Core())
	f.mu.Lock()
	f.cache[scope] = handler
	f.mu.Unlock()

	return handler
}

// Custom handler for logger per scope

type ctxHandler struct {
	next  slog.Handler
	scope string // optional
}

func (h *ctxHandler) Enabled(ctx context.Context, lvl slog.Level) bool {
	return h.next.Enabled(ctx, lvl)
}

func (h *ctxHandler) Handle(ctx context.Context, rec slog.Record) error {
	if h.scope != "" {
		rec.AddAttrs(slog.String("module", h.scope))
	}

	return h.next.Handle(ctx, rec)
}

func (h *ctxHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ctxHandler{next: h.next.WithAttrs(attrs), scope: h.scope}
}

func (h *ctxHandler) WithGroup(name string) slog.Handler {
	return &ctxHandler{next: h.next.WithGroup(name), scope: h.scope}
}
