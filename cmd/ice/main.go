// SPDX-FileCopyrightText: 2025 The Pion community
// SPDX-License-Identifier: MIT

// Package main wires Ion's ICE config into a single-binary STUN/TURN service.
// If TURN is enabled, it will also serve STUN Binding on the same port(s).
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/pion/ion/v2/internal/config"
	ionICE "github.com/pion/ion/v2/internal/ice"
	"github.com/pion/ion/v2/internal/logger"
	"github.com/pion/turn/v4"
	"github.com/spf13/pflag"
)

func main() {
	config.RegisterFlags(pflag.CommandLine)
	pflag.Parse()

	cfg, err := config.Load(pflag.CommandLine)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	lf, err := logger.NewLoggerFactory(
		logger.Options{
			DefaultWriter: config.WriterStderr,
			Format:        cfg.Telemetry.Logs.Format,
			DefaultLevel:  cfg.Telemetry.Logs.Level,
		},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "loggerFactory error: %v\n", err)
		os.Exit(1)
	}

	ctx := lf.BuildLoggerForCtx(context.Background(), "ion-iceServer")
	lgr := lf.FromCtx(ctx)

	if cfg.ICE.ICEMode() == ionICE.Disabled {
		lgr.Info("both STUN and TURN disabled; exit")
		os.Exit(0)
	}

	// Graceful shutdown context via signals.
	ctx, stopSignals := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()

	// STUN-only endpoints (separate from TURN/STUN shared ones).
	_, stopSTUN, err := startStunOnlyServer(ctx, cfg.ICE, lf)
	if err != nil {
		lgr.Error(fmt.Sprintf("stun-only server: %v", err))
	}
	if stopSTUN != nil {
		defer stopSTUN()
	}

	// TURN(+STUN on same port) endpoints.
	_, stopTURNSTUN, err := startTURNSTUNServer(ctx, cfg.ICE, lf)
	if err != nil {
		lgr.Error(fmt.Sprintf("turn-stun server: %v", err))
	}
	if stopTURNSTUN != nil {
		defer stopTURNSTUN()
	}

	// Block until signal.
	<-ctx.Done()
}

// closerStack closes in LIFO order.
type closerStack struct {
	list []io.Closer
}

func (c *closerStack) Add(cs ...io.Closer) {
	c.list = append(c.list, cs...)
}

func (c *closerStack) CloseAll() {
	for i := len(c.list) - 1; i >= 0; i-- {
		_ = c.list[i].Close()
	}
}

// startStunOnlyServer starts a STUN Binding server on dedicated endpoints (no TURN).
func startStunOnlyServer(
	parent context.Context,
	cfg ionICE.ICEConfig,
	lf *logger.LoggerFactory,
) (*turn.Server, func(), error) {
	ctx := lf.BuildLoggerForCtx(parent, "stun-only")
	lgr := lf.FromCtx(ctx)

	lc := net.ListenConfig{}
	var (
		pcConfs []turn.PacketConnConfig
		lnConfs []turn.ListenerConfig // reserved for future TCP support
	)

	udpAddr, err := cfg.STUNOnlyEndpoint(ionICE.NetworkUDP) // nolint:contextcheck
	if err != nil {
		lgr.Error(err.Error())

		return nil, nil, err
	}
	tcpAddr, err := cfg.STUNOnlyEndpoint(ionICE.NetworkTCP) // nolint:contextcheck
	if err != nil {
		lgr.Error(err.Error())

		return nil, nil, err
	}

	if udpAddr == "" { // no implementation on TCP yet
		return nil, nil, nil
	}

	var closers closerStack

	if udpAddr != "" {
		lgr.Info(fmt.Sprintf("STUN-only UDP endpoint on %s", udpAddr))

		var pc net.PacketConn
		pc, err = lc.ListenPacket(ctx, "udp", udpAddr)
		if err != nil {
			lgr.Error(err.Error())
			closers.CloseAll()

			return nil, nil, err
		}
		pcConfs = append(pcConfs, turn.PacketConnConfig{PacketConn: pc})
		closers.Add(pc)
	}

	if tcpAddr != "" {
		// Not yet implemented by this binary (pion/turn supports TCP for TURN,
		// but STUN-only over TCP here is intentionally deferred).
		lgr.Warn("STUN-only over TCP not supported yet")
	}

	srv, err := turn.NewServer(turn.ServerConfig{
		PacketConnConfigs: pcConfs,
		ListenerConfigs:   lnConfs,
		LoggerFactory:     lf.NewPionAdaptor(ctx),
	})
	if err != nil {
		lgr.Error(err.Error())
		closers.CloseAll()

		return nil, nil, err
	}

	stop := func() {
		_ = srv.Close()
		closers.CloseAll()
	}

	go func() {
		<-ctx.Done()
		stop()
	}()

	return srv, stop, nil
}

// startTURNSTUNServer starts TURN (and STUN on same ports) based on config.
func startTURNSTUNServer( //nolint:cyclop
	parent context.Context,
	cfg ionICE.ICEConfig,
	lf *logger.LoggerFactory,
) (*turn.Server, func(), error) {
	ctx := lf.BuildLoggerForCtx(parent, "turn-stun")
	lgr := lf.FromCtx(ctx)
	lc := net.ListenConfig{}

	udpAddr, err := cfg.TURNSTUNEndpoint(ionICE.NetworkUDP) // nolint:contextcheck
	if err != nil {
		lgr.Error(err.Error())

		return nil, nil, err
	}
	tcpAddr, err := cfg.TURNSTUNEndpoint(ionICE.NetworkTCP) // nolint:contextcheck
	if err != nil {
		lgr.Error(err.Error())

		return nil, nil, err
	}
	tlsAddr := cfg.TURN.TLS.Endpoint

	if udpAddr == "" && tcpAddr == "" && tlsAddr == "" {
		lgr.Info("no TURN-STUN server configured")

		return nil, nil, nil
	}

	realm := cfg.TURN.Realm
	authHandler := makeAuth(ctx, lf, cfg.TURN)
	relayGen := makeRelay(cfg.TURN)

	var (
		pcConfs []turn.PacketConnConfig
		lnConfs []turn.ListenerConfig
		closers closerStack
	)

	// UDP
	if udpAddr != "" {
		lgr.Info(fmt.Sprintf("TURN-STUN UDP endpoint on %s (realm=%s)", udpAddr, realm))
		pc, errUDP := lc.ListenPacket(ctx, "udp", udpAddr)
		if errUDP != nil {
			lgr.Error(errUDP.Error())
			closers.CloseAll()

			return nil, nil, fmt.Errorf("udp listen %q: %w", udpAddr, errUDP)
		}
		pcConfs = append(pcConfs, turn.PacketConnConfig{
			PacketConn:            pc,
			RelayAddressGenerator: relayGen,
		})
		closers.Add(pc)
	}

	// TCP
	if tcpAddr != "" {
		lgr.Info(fmt.Sprintf("TURN-STUN TCP endpoint on %s (realm=%s)", tcpAddr, realm))
		ln, errTCP := lc.Listen(ctx, "tcp", tcpAddr)
		if errTCP != nil {
			lgr.Error(errTCP.Error())
			closers.CloseAll()

			return nil, nil, fmt.Errorf("tcp listen %q: %w", tcpAddr, errTCP)
		}
		lnConfs = append(lnConfs, turn.ListenerConfig{
			Listener:              ln,
			RelayAddressGenerator: relayGen,
		})
		closers.Add(ln)
	}

	// TLS
	if tlsAddr != "" {
		lgr.Info(fmt.Sprintf("TURN TLS endpoint on %s (realm=%s)", tlsAddr, realm))
		lnConf, errTLS := setupTLSEndpoint(ctx, lc, tlsAddr, cfg.TURN.TLS, relayGen, &closers)
		if errTLS != nil {
			lgr.Error(errTLS.Error())
			closers.CloseAll()

			return nil, nil, errTLS
		}
		lnConfs = append(lnConfs, lnConf)
	}

	srv, err := turn.NewServer(turn.ServerConfig{
		Realm:             realm,
		LoggerFactory:     lf.NewPionAdaptor(ctx),
		AuthHandler:       authHandler,
		PacketConnConfigs: pcConfs,
		ListenerConfigs:   lnConfs,
	})
	if err != nil {
		lgr.Error(err.Error())
		closers.CloseAll()

		return nil, nil, err
	}

	stop := func() {
		_ = srv.Close()
		closers.CloseAll()
	}

	go func() {
		<-ctx.Done()
		stop()
	}()

	return srv, stop, nil
}

// setupTLSEndpoint wires a TLS listener for TURN and returns a ListenerConfig.
// It only adds listeners to closers on success; on error, the caller can CloseAll().
func setupTLSEndpoint(
	ctx context.Context,
	lc net.ListenConfig,
	tlsAddr string,
	tlsCfg ionICE.TLSConfig,
	relayGen turn.RelayAddressGenerator,
	closers *closerStack,
) (turn.ListenerConfig, error) {
	baseLn, err := lc.Listen(ctx, "tcp", tlsAddr)
	if err != nil {
		return turn.ListenerConfig{}, fmt.Errorf("tls listen %q: %w", tlsAddr, err)
	}

	cert, err := tls.LoadX509KeyPair(tlsCfg.Cert, tlsCfg.Key)
	if err != nil {
		_ = baseLn.Close()

		return turn.ListenerConfig{}, fmt.Errorf("load tls cert: %w", err)
	}
	tlsVerison := tlsCfg.GetTLSVersion()

	//nolint:gosec // G402 goes below 1.2 only when user force it
	tlsLn := tls.NewListener(baseLn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tlsVerison,
	})

	// Add to closer stack only after everything succeeded.
	closers.Add(tlsLn, baseLn)

	return turn.ListenerConfig{
		Listener:              tlsLn,
		RelayAddressGenerator: relayGen,
	}, nil
}

// makeRelay returns the RelayAddressGenerator for configuration.
func makeRelay(cfg ionICE.TURNConfig) turn.RelayAddressGenerator {
	return &turn.RelayAddressGeneratorPortRange{
		Address:      cfg.Address,
		MinPort:      cfg.PortRangeMin,
		MaxPort:      cfg.PortRangeMax,
		RelayAddress: net.ParseIP(cfg.PublicIP),
	}
}

// makeAuth returns an AuthHandler for TURN based on config.
func makeAuth(ctx context.Context, lf *logger.LoggerFactory, cfg ionICE.TURNConfig) turn.AuthHandler {
	lgr := lf.FromCtx(ctx)

	switch strings.ToLower(strings.TrimSpace(cfg.Auth)) {
	case "", "static":
		users := map[string]string{}
		if cfg.User != "" {
			users[cfg.User] = cfg.Password
		}

		return func(username, realm string, _ net.Addr) ([]byte, bool) {
			if realm != cfg.Realm {
				return nil, false
			}
			pw, ok := users[username]
			if !ok {
				return nil, false
			}

			return turn.GenerateAuthKey(username, realm, pw), true
		}

	case "long-term", "longterm", "long_term":
		secret := strings.TrimSpace(cfg.Secret)
		if secret == "" {
			lgr.Warn("long-term auth requested but secret is empty; rejecting all auth")

			return func(string, string, net.Addr) ([]byte, bool) { return nil, false }
		}
		// nolint:contextcheck // pion/turn logger doesn't take context.
		return turn.NewLongTermAuthHandler(secret, lf.NewPionAdaptor(ctx).NewLogger("ion-iceServer"))

	default:
		lgr.Warn(fmt.Sprintf("unknown auth=%q; rejecting all auth", cfg.Auth))

		return func(string, string, net.Addr) ([]byte, bool) { return nil, false }
	}
}
