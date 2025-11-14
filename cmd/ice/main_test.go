// SPDX-FileCopyrightText: 2025 The Pion community
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pion/ion/v2/internal/config"
	ionICE "github.com/pion/ion/v2/internal/ice"
	"github.com/pion/ion/v2/internal/logger"
	"github.com/pion/turn/v4"
	"github.com/stretchr/testify/require"
)

// --- shared test constants (avoid goconst) ---.
const (
	testScopeGeneric = "test"

	loopbackEphemeral = "127.0.0.1:0"
	anyUDPEphemeral   = "0.0.0.0:0"

	realmIon   = "ion"
	authStatic = "static"

	userAlice   = "alice"
	passSecret  = "secret"
	passPwd     = "password"
	passCorrect = "correct-password"

	pubIP1 = "127.0.0.1"
	pubIP2 = "127.0.0.2"
	pubIP3 = "127.0.0.3"

	portMin50000 = 50000
	portMax50010 = 50010
	portMax50005 = 50005

	swIonTests = "ion-ice-tests"
)

// --- helpers ---

func safeClose(t *testing.T, c io.Closer) {
	t.Helper()
	if c == nil {
		return
	}

	if err := c.Close(); err != nil {
		t.Logf("failed to close %T: %v", c, err)
	}
}

func testLoggerFactory(t *testing.T) *logger.LoggerFactory {
	t.Helper()
	lf, err := logger.NewLoggerFactory(logger.Options{
		DefaultWriter: config.WriterStderr,
		Format:        config.LogFormatText,
		DefaultLevel:  "debug",
	})
	require.NoError(t, err)

	return lf
}

// self-signed cert to temp files, returns paths.
func writeSelfSignedCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"ion-tests"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)

	certOut := filepath.Join(dir, "cert.pem")
	keyOut := filepath.Join(dir, "key.pem")

	{
		f, err := os.Create(certOut) // #nosec G304
		require.NoError(t, err)
		defer safeClose(t, f)
		require.NoError(t, pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	{
		f, err := os.Create(keyOut) // #nosec G304
		require.NoError(t, err)
		defer safeClose(t, f)
		b := x509.MarshalPKCS1PrivateKey(priv)
		require.NoError(t, pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}))
	}

	return certOut, keyOut
}

// --- tests ---

func TestStartStunOnlyServer_NoneConfigured(t *testing.T) {
	lf := testLoggerFactory(t)
	ctx := lf.BuildLoggerForCtx(context.Background(), testScopeGeneric)

	// STUN disabled → STUNOnlyEndpoint("") should be empty via config
	cfg := ionICE.DefaultICEConfig()
	cfg.STUN.Enabled = false
	cfg.TURN.Enabled = false

	srv, stop, err := startStunOnlyServer(ctx, cfg, lf)
	require.NoError(t, err)
	require.Nil(t, srv)
	require.Nil(t, stop)
}

func TestStartStunOnlyServer_UDPOnly_Ephemeral(t *testing.T) {
	lf := testLoggerFactory(t)
	ctx := lf.BuildLoggerForCtx(context.Background(), testScopeGeneric)

	cfg := ionICE.DefaultICEConfig()
	cfg.STUN.Enabled = true
	cfg.TURN.Enabled = false
	// Explicit UDP endpoint, TCP empty
	cfg.STUN.UDPEndpoint = loopbackEphemeral
	cfg.STUN.TCPEndpoint = ""

	srv, stop, err := startStunOnlyServer(ctx, cfg, lf)
	require.NoError(t, err)
	require.NotNil(t, srv)
	require.NotNil(t, stop)

	// Stop should be idempotent & not panic
	stop()
}

func TestStartTURNSTUNServer_NoneConfigured(t *testing.T) {
	lf := testLoggerFactory(t)
	ctx := lf.BuildLoggerForCtx(context.Background(), testScopeGeneric)

	cfg := ionICE.DefaultICEConfig()
	cfg.STUN.Enabled = false
	cfg.TURN.Enabled = false
	cfg.TURN.TLS.Endpoint = ""

	srv, stop, err := startTURNSTUNServer(ctx, cfg, lf)
	require.NoError(t, err)
	require.Nil(t, srv)
	require.Nil(t, stop)
}

func TestStartTURNSTUNServer_UDP_TCP_Ephemeral(t *testing.T) {
	lf := testLoggerFactory(t)
	ctx := lf.BuildLoggerForCtx(context.Background(), testScopeGeneric)

	cfg := ionICE.DefaultICEConfig()
	cfg.STUN.Enabled = true
	cfg.TURN.Enabled = true
	// Share UDP/TCP ports (same-port STUN+TURN)
	cfg.STUN.UDPEndpoint = loopbackEphemeral
	cfg.TURN.UDPEndpoint = cfg.STUN.UDPEndpoint
	cfg.STUN.TCPEndpoint = loopbackEphemeral
	cfg.TURN.TCPEndpoint = cfg.STUN.TCPEndpoint
	cfg.TURN.Realm = realmIon
	cfg.TURN.Auth = authStatic
	cfg.TURN.User = userAlice
	cfg.TURN.Password = passPwd
	cfg.TURN.PortRangeMin = portMin50000
	cfg.TURN.PortRangeMax = portMax50010
	cfg.TURN.PublicIP = pubIP1

	srv, stop, err := startTURNSTUNServer(ctx, cfg, lf)
	require.NoError(t, err)
	require.NotNil(t, srv)
	require.NotNil(t, stop)
	stop()
}

func TestStartTURNSTUNServer_TLS_MissingCertKey_Err(t *testing.T) {
	lf := testLoggerFactory(t)
	ctx := lf.BuildLoggerForCtx(context.Background(), testScopeGeneric)

	cfg := ionICE.DefaultICEConfig()
	cfg.STUN.Enabled = true
	cfg.TURN.Enabled = true
	cfg.STUN.UDPEndpoint = loopbackEphemeral
	cfg.TURN.UDPEndpoint = cfg.STUN.UDPEndpoint
	cfg.TURN.Realm = realmIon
	cfg.TURN.Auth = authStatic
	cfg.TURN.User = userAlice
	cfg.TURN.Password = passPwd
	cfg.TURN.TLS.Endpoint = loopbackEphemeral // enabled
	cfg.TURN.TLS.Cert = ""                    // missing
	cfg.TURN.TLS.Key = ""                     // missing

	srv, stop, err := startTURNSTUNServer(ctx, cfg, lf)
	require.Error(t, err)
	require.Nil(t, srv)
	require.Nil(t, stop)
}

func TestStartTURNSTUNServer_TLS_WithCertKey_OK(t *testing.T) {
	lf := testLoggerFactory(t)
	ctx := lf.BuildLoggerForCtx(context.Background(), testScopeGeneric)

	tmp := t.TempDir()
	certFile, keyFile := writeSelfSignedCert(t, tmp)

	cfg := ionICE.DefaultICEConfig()
	cfg.STUN.Enabled = true
	cfg.TURN.Enabled = true
	cfg.STUN.UDPEndpoint = loopbackEphemeral
	cfg.TURN.UDPEndpoint = cfg.STUN.UDPEndpoint
	cfg.TURN.Realm = realmIon
	cfg.TURN.Auth = authStatic
	cfg.TURN.User = userAlice
	cfg.TURN.Password = passPwd
	cfg.TURN.TLS.Endpoint = loopbackEphemeral
	cfg.TURN.TLS.Cert = certFile
	cfg.TURN.TLS.Key = keyFile
	cfg.TURN.PortRangeMin = portMin50000
	cfg.TURN.PortRangeMax = portMax50005
	cfg.TURN.PublicIP = pubIP1

	srv, stop, err := startTURNSTUNServer(ctx, cfg, lf)
	require.NoError(t, err)
	require.NotNil(t, srv)
	require.NotNil(t, stop)
	stop()
}

func TestMakeAuth_Static(t *testing.T) {
	lf := testLoggerFactory(t)
	ctx := lf.BuildLoggerForCtx(context.Background(), testScopeGeneric)

	tcfg := ionICE.TURNConfig{
		Realm:    realmIon,
		Auth:     authStatic,
		User:     userAlice,
		Password: passSecret,
	}
	h := makeAuth(ctx, lf, tcfg)

	key, ok := h(userAlice, realmIon, &net.UDPAddr{})
	require.True(t, ok)
	require.NotNil(t, key)

	_, ok = h("bob", realmIon, &net.UDPAddr{})
	require.False(t, ok)

	_, ok = h(userAlice, "wrong-realm", &net.UDPAddr{})
	require.False(t, ok)
}

func TestMakeAuth_LongTerm_EmptySecret_RejectAll(t *testing.T) {
	lf := testLoggerFactory(t)
	ctx := lf.BuildLoggerForCtx(context.Background(), testScopeGeneric)

	tcfg := ionICE.TURNConfig{
		Realm: realmIon,
		Auth:  "longterm",
		// Secret empty
	}
	h := makeAuth(ctx, lf, tcfg)

	_, ok := h("any", realmIon, &net.UDPAddr{})
	require.False(t, ok)
}

func TestMakeAuth_UnknownScheme_RejectAll(t *testing.T) {
	lf := testLoggerFactory(t)
	ctx := lf.BuildLoggerForCtx(context.Background(), testScopeGeneric)

	tcfg := ionICE.TURNConfig{
		Realm: realmIon,
		Auth:  "mystery-auth",
	}
	h := makeAuth(ctx, lf, tcfg)

	_, ok := h("any", realmIon, &net.UDPAddr{})
	require.False(t, ok)
}

func TestMakeRelay_PortRangeAndIP(t *testing.T) {
	turnCfg := ionICE.TURNConfig{
		PortRangeMin: 49000,
		PortRangeMax: 49010,
		PublicIP:     "203.0.113.10",
	}
	gen := makeRelay(turnCfg)

	rg, ok := gen.(*turn.RelayAddressGeneratorPortRange)
	require.True(t, ok)
	require.Equal(t, uint16(49000), rg.MinPort)
	require.Equal(t, uint16(49010), rg.MaxPort)
	require.Equal(t, net.ParseIP("203.0.113.10"), rg.RelayAddress)
}

func TestStopIsIdempotent(t *testing.T) {
	lf := testLoggerFactory(t)
	ctx, cancel := context.WithCancel(context.Background())
	ctx = lf.BuildLoggerForCtx(ctx, testScopeGeneric)

	cfg := ionICE.DefaultICEConfig()
	cfg.STUN.Enabled = true
	cfg.TURN.Enabled = true
	cfg.STUN.UDPEndpoint = loopbackEphemeral
	cfg.TURN.UDPEndpoint = cfg.STUN.UDPEndpoint
	cfg.TURN.Realm = realmIon
	cfg.TURN.Auth = authStatic
	cfg.TURN.User = userAlice
	cfg.TURN.Password = passPwd
	cfg.TURN.PublicIP = pubIP1

	srv, stop, err := startTURNSTUNServer(ctx, cfg, lf)
	require.NoError(t, err)
	require.NotNil(t, srv)
	require.NotNil(t, stop)

	// Cancel context triggers internal stop
	cancel()
	// Call stop again; should not panic
	stop()
}

/***************
 * Test helpers
 ***************/

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", loopbackEphemeral) //nolint:noctx
	require.NoError(t, err)
	defer safeClose(t, pc)

	return pc.LocalAddr().String()
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", loopbackEphemeral) //nolint:noctx
	require.NoError(t, err)
	safeClose(t, ln)

	return ln.Addr().String()
}

/*******************************
 * TURN client integration tests
 *******************************/

// Allocates over UDP with correct static creds.
func TestTURNClient_Allocate_UDP_Success(t *testing.T) {
	lf := testLoggerFactory(t)
	ctx := lf.BuildLoggerForCtx(context.Background(), "test-turn-alloc-udp")

	udpAddr := freeUDPAddr(t) // reserve/learn an ephemeral port, then release

	// Configure server to listen on that known UDP addr; TURN+STUN same-port mode.
	cfg := ionICE.DefaultICEConfig()
	cfg.STUN.Enabled = true
	cfg.TURN.Enabled = true
	cfg.STUN.UDPEndpoint = udpAddr
	cfg.TURN.UDPEndpoint = udpAddr
	cfg.TURN.Realm = realmIon
	cfg.TURN.Auth = authStatic
	cfg.TURN.User = userAlice
	cfg.TURN.Password = passPwd
	cfg.TURN.PortRangeMin = portMin50000
	cfg.TURN.PortRangeMax = portMax50010
	cfg.TURN.PublicIP = pubIP2

	// Start server
	srv, stop, err := startTURNSTUNServer(ctx, cfg, lf)
	require.NoError(t, err)
	require.NotNil(t, srv)
	require.NotNil(t, stop)
	defer stop()

	// TURN client bound to an ephemeral local UDP socket
	pconn, err := net.ListenPacket("udp4", anyUDPEphemeral) //nolint:noctx
	require.NoError(t, err)
	defer safeClose(t, pconn)

	cl, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: udpAddr,       // not needed here
		TURNServerAddr: udpAddr,       // point to our server
		Conn:           pconn,         // client's UDP socket
		Username:       cfg.TURN.User, // static auth
		Password:       cfg.TURN.Password,
		Realm:          cfg.TURN.Realm,
		LoggerFactory:  lf.NewPionAdaptor(ctx),
		Software:       swIonTests,
	})
	require.NoError(t, err)
	defer cl.Close()

	require.NoError(t, cl.Listen())

	// Allocate relay
	relayConn, err := cl.Allocate()
	require.NoError(t, err)
	require.NotEmpty(t, relayConn.LocalAddr().String())
	host, _, err := net.SplitHostPort(relayConn.LocalAddr().String())
	require.NoError(t, err)
	require.Equal(t, host, cfg.TURN.PublicIP)

	// Smoke: binding request should return mapped addr
	mapped, err := cl.SendBindingRequest()
	require.NoError(t, err)
	require.NotNil(t, mapped)
}

// Fails allocation with wrong password.
func TestTURNClient_Allocate_UDP_BadCreds_Fails(t *testing.T) {
	lf := testLoggerFactory(t)
	ctx := lf.BuildLoggerForCtx(context.Background(), "test-turn-alloc-badcreds")

	udpAddr := freeUDPAddr(t)

	cfg := ionICE.DefaultICEConfig()
	cfg.STUN.Enabled = true
	cfg.TURN.Enabled = true
	cfg.STUN.UDPEndpoint = udpAddr
	cfg.TURN.UDPEndpoint = udpAddr
	cfg.TURN.Realm = realmIon
	cfg.TURN.Auth = authStatic
	cfg.TURN.User = userAlice
	cfg.TURN.Password = passCorrect
	cfg.TURN.PortRangeMin = portMin50000
	cfg.TURN.PortRangeMax = portMax50010
	cfg.TURN.PublicIP = pubIP2

	srv, stop, err := startTURNSTUNServer(ctx, cfg, lf)
	require.NoError(t, err)
	require.NotNil(t, srv)
	require.NotNil(t, stop)
	defer stop()

	pconn, err := net.ListenPacket("udp4", anyUDPEphemeral) //nolint:noctx
	require.NoError(t, err)
	defer safeClose(t, pconn)

	cl, err := turn.NewClient(&turn.ClientConfig{
		TURNServerAddr: udpAddr,
		Conn:           pconn,
		Username:       userAlice,
		Password:       "wrong-password",
		Realm:          realmIon,
		LoggerFactory:  lf.NewPionAdaptor(ctx),
		Software:       swIonTests,
	})
	require.NoError(t, err)
	defer cl.Close()

	require.NoError(t, cl.Listen())
	_, err = cl.Allocate()
	require.Error(t, err)
}

func TestTURNClient_CreatePermission_UDP(t *testing.T) {
	lf := testLoggerFactory(t)
	ctx := lf.BuildLoggerForCtx(context.Background(), "test-turn-permission")

	udpAddr := freeUDPAddr(t)

	cfg := ionICE.DefaultICEConfig()
	cfg.STUN.Enabled = true
	cfg.TURN.Enabled = true
	cfg.STUN.UDPEndpoint = udpAddr
	cfg.TURN.UDPEndpoint = udpAddr
	cfg.TURN.Realm = realmIon
	cfg.TURN.Auth = authStatic
	cfg.TURN.User = userAlice
	cfg.TURN.Password = passPwd
	cfg.TURN.PortRangeMin = portMin50000
	cfg.TURN.PortRangeMax = portMax50005
	cfg.TURN.PublicIP = pubIP2

	srv, stop, err := startTURNSTUNServer(ctx, cfg, lf)
	require.NoError(t, err)
	require.NotNil(t, srv)
	require.NotNil(t, stop)
	defer stop()

	pconn, err := net.ListenPacket("udp4", anyUDPEphemeral) //nolint:noctx
	require.NoError(t, err)
	defer safeClose(t, pconn)

	cl, err := turn.NewClient(&turn.ClientConfig{
		TURNServerAddr: udpAddr,
		Conn:           pconn,
		Username:       cfg.TURN.User,
		Password:       cfg.TURN.Password,
		Realm:          cfg.TURN.Realm,
		LoggerFactory:  lf.NewPionAdaptor(ctx),
		Software:       swIonTests,
	})
	require.NoError(t, err)
	defer cl.Close()

	require.NoError(t, cl.Listen())
	_, err = cl.Allocate()
	require.NoError(t, err)

	// For permission target, we can just use localhost IP; TURN requires an IP
	target := &net.UDPAddr{IP: net.ParseIP(pubIP1)}
	require.NotNil(t, target)

	require.NoError(t, cl.CreatePermission(target))
}

func TestTURNClient_Allocate_TCP_Success(t *testing.T) {
	lf := testLoggerFactory(t)
	ctx := lf.BuildLoggerForCtx(context.Background(), "test-turn-alloc-tcp")

	tcpAddr := freeTCPAddr(t)

	cfg := ionICE.DefaultICEConfig()
	cfg.STUN.Enabled = true
	cfg.TURN.Enabled = true
	cfg.STUN.TCPEndpoint = tcpAddr
	cfg.TURN.TCPEndpoint = tcpAddr
	cfg.TURN.Realm = realmIon
	cfg.TURN.Auth = authStatic
	cfg.TURN.User = userAlice
	cfg.TURN.Password = passPwd
	cfg.TURN.PortRangeMin = portMin50000
	cfg.TURN.PortRangeMax = portMax50010
	cfg.TURN.PublicIP = pubIP3

	srv, stop, err := startTURNSTUNServer(ctx, cfg, lf)
	require.NoError(t, err)
	require.NotNil(t, srv)
	require.NotNil(t, stop)
	defer stop()

	// For TCP, pion/turn’s client can be configured with a net.Conn
	conn, err := net.DialTimeout("tcp", tcpAddr, 2*time.Second) //nolint:noctx
	require.NoError(t, err)
	defer safeClose(t, conn)

	client, err := turn.NewClient(&turn.ClientConfig{
		TURNServerAddr: tcpAddr,
		Conn:           turn.NewSTUNConn(conn),
		Username:       cfg.TURN.User,
		Password:       cfg.TURN.Password,
		Realm:          cfg.TURN.Realm,
		LoggerFactory:  lf.NewPionAdaptor(ctx),
		Software:       swIonTests,
	})
	require.NoError(t, err)
	defer client.Close()
	require.NoError(t, client.Listen())
	relayConn, err := client.Allocate()
	require.NoError(t, err)
	require.NotEmpty(t, relayConn.LocalAddr().String())
	host, _, err := net.SplitHostPort(relayConn.LocalAddr().String())
	require.NoError(t, err)
	require.Equal(t, host, cfg.TURN.PublicIP)
}
