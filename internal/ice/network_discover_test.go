// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/require"
)

// newTestLogger returns a slog.Logger that discards all output.
func newTestLogger(tb testing.TB) *slog.Logger {
	tb.Helper()

	return slog.New(
		slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}),
	)
}

func TestDiscoverLocalIP_BestEffort(t *testing.T) {
	// First check if this machine even has a non-loopback IPv4 address.
	addrs, err := net.InterfaceAddrs()
	require.NoError(t, err)

	hasNonLoopbackIPv4 := false

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			hasNonLoopbackIPv4 = true

			break
		}
	}

	if !hasNonLoopbackIPv4 {
		t.Skip("no non-loopback IPv4 addresses on this host; skipping DiscoverLocalIP happy-path test")
	}

	ipStr, err := DiscoverLocalIP()
	require.NoError(t, err)

	ip := net.ParseIP(ipStr)
	require.NotNil(t, ip, "DiscoverLocalIP should return a parseable IP")
	require.NotNil(t, ip.To4(), "DiscoverLocalIP should return an IPv4 address")
}

func TestConnect_Success(t *testing.T) {
	log := newTestLogger(t)

	conn, err := connect("127.0.0.1:0", log)
	require.NoError(t, err)
	require.NotNil(t, conn)

	defer func() {
		if cerr := conn.Close(); cerr != nil {
			t.Logf("failed to close stunServerConn: %v", cerr)
		}
	}()

	require.NotNil(t, conn.conn)
	require.NotNil(t, conn.LocalAddr)
	require.NotNil(t, conn.RemoteAddr)
	require.NotNil(t, conn.messageChan)
}

func TestConnect_InvalidAddress(t *testing.T) {
	log := newTestLogger(t)

	conn, err := connect("this-is-not-a-valid-host:9999", log)
	require.Error(t, err)
	require.Nil(t, conn)
	require.ErrorIs(t, err, errConnectStun)
}

func TestStunServerConn_Close(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0") //nolint:noctx
	require.NoError(t, err)

	defer func() {
		if cerr := pc.Close(); cerr != nil {
			t.Logf("failed to close PacketConn: %v", cerr)
		}
	}()

	s := &stunServerConn{
		conn:      pc,
		LocalAddr: pc.LocalAddr(),
	}

	err = s.Close()
	require.NoError(t, err)
}

func TestRoundTrip_Success(t *testing.T) {
	log := newTestLogger(t)

	pc, err := net.ListenPacket("udp4", "127.0.0.1:0") //nolint:noctx
	require.NoError(t, err)

	defer func() {
		if cerr := pc.Close(); cerr != nil {
			t.Logf("failed to close PacketConn: %v", cerr)
		}
	}()

	remote := pc.LocalAddr()

	srv := &stunServerConn{ //nolint:forcetypeassert
		conn:        pc,
		LocalAddr:   pc.LocalAddr(),
		RemoteAddr:  remote.(*net.UDPAddr),
		messageChan: make(chan *stun.Message, 1),
	}

	respMsg := stun.MustBuild(stun.TransactionID, stun.BindingSuccess)

	go func() {
		srv.messageChan <- respMsg
	}()

	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	got, err := srv.roundTrip(req, srv.RemoteAddr, log)
	require.NoError(t, err)
	require.NotNil(t, got)
}

func TestRoundTrip_WriteError(t *testing.T) {
	log := newTestLogger(t)

	pc, err := net.ListenPacket("udp4", "127.0.0.1:0") //nolint:noctx
	require.NoError(t, err)

	if cerr := pc.Close(); cerr != nil {
		t.Logf("failed to close PacketConn: %v", cerr)
	}

	s := &stunServerConn{
		conn:        pc,
		messageChan: make(chan *stun.Message),
	}

	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	got, err := s.roundTrip(req, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}, log)
	require.Nil(t, got)
	require.Error(t, err)
	require.ErrorIs(t, err, errRoundTrip)
}

func TestRoundTrip_ChannelClosed(t *testing.T) {
	log := newTestLogger(t)

	pc, err := net.ListenPacket("udp4", "127.0.0.1:0") //nolint:noctx
	require.NoError(t, err)

	defer func() {
		if cerr := pc.Close(); cerr != nil {
			t.Logf("failed to close PacketConn: %v", cerr)
		}
	}()

	ch := make(chan *stun.Message)
	close(ch)

	s := &stunServerConn{ //nolint:forcetypeassert
		conn:        pc,
		LocalAddr:   pc.LocalAddr(),
		RemoteAddr:  pc.LocalAddr().(*net.UDPAddr),
		messageChan: ch,
	}

	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	got, err := s.roundTrip(req, s.RemoteAddr, log)
	require.Nil(t, got)
	require.ErrorIs(t, err, errResponseMessage)
}

func TestListen_ClosesChannelOnReadError(t *testing.T) {
	log := newTestLogger(t)

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)

	msgCh := listen(udpConn, log)

	if cerr := udpConn.Close(); cerr != nil {
		t.Logf("failed to close UDPConn: %v", cerr)
	}

	if _, ok := <-msgCh; ok {
		require.True(t, ok)
	}
}

func TestParse_ReturnsAttributesWhenPresent(t *testing.T) {
	log := newTestLogger(t)

	var msg stun.Message
	msg.Type = stun.BindingSuccess
	msg.TransactionID = [stun.TransactionIDSize]byte{1, 2, 3, 4}

	xorAddr := &stun.XORMappedAddress{
		IP:   net.IPv4(192, 0, 2, 1),
		Port: 3478,
	}
	require.NoError(t, xorAddr.AddTo(&msg))

	otherAddr := &stun.OtherAddress{
		IP:   net.IPv4(192, 0, 2, 2),
		Port: 3479,
	}
	require.NoError(t, otherAddr.AddTo(&msg))

	respOrigin := &stun.ResponseOrigin{
		IP:   net.IPv4(192, 0, 2, 3),
		Port: 3480,
	}
	require.NoError(t, respOrigin.AddTo(&msg))

	mappedAddr := &stun.MappedAddress{
		IP:   net.IPv4(192, 0, 2, 4),
		Port: 3481,
	}
	require.NoError(t, mappedAddr.AddTo(&msg))

	software := &stun.Software{}
	require.NoError(t, software.AddTo(&msg))

	ret := parse(&msg, log)

	require.NotNil(t, ret.xorAddr, "xorAddr should be non-nil when XOR-MAPPED-ADDRESS is present")
	require.NotNil(t, ret.otherAddr, "otherAddr should be non-nil when OTHER-ADDRESS is present")
	require.NotNil(t, ret.respOrigin, "respOrigin should be non-nil when RESPONSE-ORIGIN is present")
	require.NotNil(t, ret.mappedAddr, "mappedAddr should be non-nil when MAPPED-ADDRESS is present")
	require.NotNil(t, ret.software, "software should be non-nil when SOFTWARE is present")
}

func TestParse_AllowsMissingAttributes(t *testing.T) {
	log := newTestLogger(t)

	msg := stun.MustBuild(stun.TransactionID, stun.BindingSuccess)

	ret := parse(msg, log)

	require.Nil(t, ret.xorAddr)
	require.Nil(t, ret.otherAddr)
	require.Nil(t, ret.respOrigin)
	require.Nil(t, ret.mappedAddr)
	require.Nil(t, ret.software)
}

func TestDiscoverNatMapping_ConnectError(t *testing.T) {
	log := newTestLogger(t)

	_, err := DiscoverNatMapping("invalid-address", log)
	require.Error(t, err)
	require.ErrorIs(t, err, errDiscoverMapping)
}

type testStunServer struct {
	conn    *net.UDPConn
	handler func(call int, req *stun.Message) (*stun.Message, bool)
	callNum int
	mu      sync.Mutex
}

func newTestStunServer(t *testing.T) *testStunServer {
	t.Helper()

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := net.ListenUDP("udp4", addr)
	require.NoError(t, err)

	srv := &testStunServer{
		conn: conn,
	}

	go srv.serve(t)

	t.Cleanup(func() {
		if cerr := srv.conn.Close(); cerr != nil {
			t.Logf("failed to close test STUN server: %v", cerr)
		}
	})

	return srv
}

func (s *testStunServer) Addr() string {
	return s.conn.LocalAddr().String()
}

func (s *testStunServer) serve(t *testing.T) {
	t.Helper()
	buf := make([]byte, 1500)

	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		msg := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
		if decodeErr := msg.Decode(); err != nil {
			t.Logf("failed to decode STUN request: %v", decodeErr)

			continue
		}

		s.mu.Lock()
		s.callNum++
		call := s.callNum
		s.mu.Unlock()

		resp, ok := s.handler(call, msg)
		if !ok || resp == nil {
			continue
		}

		_, err = s.conn.WriteTo(resp.Raw, addr)
		if err != nil {
			t.Logf("failed to write STUN response: %v", err)
		}
	}
}

func (s *testStunServer) SetHandler(h func(call int, req *stun.Message) (*stun.Message, bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handler = h
}

func stunResp(attrs ...stun.Setter) *stun.Message {
	return stun.MustBuild(
		attrs...,
	)
}

/* -------------------------------------------------------------
   NAT MAPPING TESTS
   ------------------------------------------------------------- */

func TestDiscoverNatMapping_NoNAT(t *testing.T) {
	log := newTestLogger(t)

	localIP, err := DiscoverLocalIP()
	if errors.Is(err, errNoLocalIPFound) {
		t.Skip()
	}
	require.NoError(t, err)

	srv := newTestStunServer(t)
	srv.SetHandler(func(call int, req *stun.Message) (*stun.Message, bool) {
		if call != 1 {
			return nil, false
		}

		//nolint:forcetypeassert
		return stunResp(
			&stun.XORMappedAddress{IP: net.ParseIP(localIP), Port: 5000},
			&stun.OtherAddress{IP: net.ParseIP("127.0.0.1"), Port: srv.conn.LocalAddr().(*net.UDPAddr).Port},
		), true
	})

	behavior, derr := DiscoverNatMapping(srv.Addr(), log)
	require.NoError(t, derr)
	require.Equal(t, NoNAT, behavior)
}

func TestDiscoverNatMapping_EpIndependent(t *testing.T) {
	log := newTestLogger(t)

	_, err := DiscoverLocalIP()
	if errors.Is(err, errNoLocalIPFound) {
		t.Skip()
	}
	require.NoError(t, err)

	srv := newTestStunServer(t)
	srv.SetHandler(func(call int, req *stun.Message) (*stun.Message, bool) {
		switch call {
		case 1:
			//nolint:forcetypeassert
			return stunResp(
				&stun.XORMappedAddress{IP: net.ParseIP("203.0.113.10"), Port: 5000},
				&stun.OtherAddress{IP: net.ParseIP("127.0.0.1"), Port: srv.conn.LocalAddr().(*net.UDPAddr).Port},
			), true
		case 2:
			return stunResp(
				&stun.XORMappedAddress{IP: net.ParseIP("203.0.113.10"), Port: 5000},
			), true
		default:
			return nil, false
		}
	})

	behavior, derr := DiscoverNatMapping(srv.Addr(), log)
	require.NoError(t, derr)
	require.Equal(t, EpIndependent, behavior)
}

func TestDiscoverNatMapping_Dependent(t *testing.T) {
	log := newTestLogger(t)

	_, err := DiscoverLocalIP()
	require.NoError(t, err)

	srv := newTestStunServer(t)
	srv.SetHandler(func(call int, req *stun.Message) (*stun.Message, bool) {
		srvPort := srv.conn.LocalAddr().(*net.UDPAddr).Port //nolint:forcetypeassert
		switch call {
		case 1:
			return stunResp(
				&stun.XORMappedAddress{IP: net.ParseIP("203.0.113.1"), Port: 5000},
				&stun.OtherAddress{IP: net.ParseIP("127.0.0.1"), Port: srvPort},
			), true

		case 2:
			return stunResp(
				&stun.XORMappedAddress{IP: net.ParseIP("203.0.113.2"), Port: 5001},
			), true

		case 3:
			return stunResp(
				&stun.XORMappedAddress{IP: net.ParseIP("203.0.113.2"), Port: 5001},
			), true
		case 4:
			return stunResp(
				&stun.XORMappedAddress{IP: net.ParseIP("203.0.113.1"), Port: 5000},
				&stun.OtherAddress{IP: net.ParseIP("127.0.0.1"), Port: srvPort},
			), true

		case 5:
			return stunResp(
				&stun.XORMappedAddress{IP: net.ParseIP("203.0.113.2"), Port: 5001},
			), true

		case 6:
			return stunResp(
				&stun.XORMappedAddress{IP: net.ParseIP("203.0.113.2"), Port: 5002},
			), true

		default:
			return nil, false
		}
	})

	behavior, err2 := DiscoverNatMapping(srv.Addr(), log)
	require.NoError(t, err2)
	require.Equal(t, AddrDependent, behavior)
	behavior, err2 = DiscoverNatMapping(srv.Addr(), log)
	require.NoError(t, err2)
	require.Equal(t, AddrEpDependent, behavior)
}

func TestDiscoverNatMapping_MissingOtherAddress(t *testing.T) {
	log := newTestLogger(t)

	_, err := DiscoverLocalIP()
	require.NoError(t, err)

	srv := newTestStunServer(t)
	srv.SetHandler(func(call int, req *stun.Message) (*stun.Message, bool) {
		return stunResp(
			&stun.XORMappedAddress{IP: net.ParseIP("203.0.113.5"), Port: 5000},
		), true
	})

	_, derr := DiscoverNatMapping(srv.Addr(), log)
	require.Error(t, derr)
	require.ErrorIs(t, derr, errDiscoverMapping)
	require.ErrorIs(t, derr, errNoOtherAddress)
}

func TestDiscoverNatMapping_Timeout(t *testing.T) {
	log := newTestLogger(t)

	_, err := DiscoverLocalIP()
	require.NoError(t, err)

	srv := newTestStunServer(t)
	srv.SetHandler(func(call int, req *stun.Message) (*stun.Message, bool) {
		return nil, false // cause timeout
	})

	start := time.Now()
	behavior, derr := DiscoverNatMapping(srv.Addr(), log)
	elapsed := time.Since(start)

	require.Equal(t, AddrEpDependent, behavior)
	require.Error(t, derr)
	require.ErrorIs(t, derr, errTimedOut)
	require.GreaterOrEqual(t, elapsed, defaultTimeout)
}

// /* -------------------------------------------------------------
//    NAT FILTERING TESTS
//    ------------------------------------------------------------- */

func TestDiscoverNatFiltering_ConnectError(t *testing.T) {
	log := newTestLogger(t)

	behavior, err := DiscoverNatFiltering("%invalid", log)
	require.Equal(t, AddrEpDependent, behavior)
	require.Error(t, err)
	require.ErrorIs(t, err, errDiscoverFiltering)
}

func TestDiscoverNatFiltering_MissingOtherAddress(t *testing.T) {
	log := newTestLogger(t)
	srv := newTestStunServer(t)
	srv.SetHandler(func(call int, req *stun.Message) (*stun.Message, bool) {
		switch call {
		case 1:
			return stunResp(
				&stun.XORMappedAddress{IP: net.ParseIP("203.0.113.10"), Port: 5000},
			), true
		default:
			return nil, false
		}
	})

	_, err := DiscoverNatFiltering(srv.Addr(), log)
	require.Error(t, err)
	require.ErrorIs(t, err, errDiscoverFiltering)
	require.ErrorIs(t, err, errNoOtherAddress)
}

func TestDiscoverNatFiltering_EpIndependent(t *testing.T) {
	log := newTestLogger(t)

	srv := newTestStunServer(t)
	srv.SetHandler(func(call int, req *stun.Message) (*stun.Message, bool) {
		switch call {
		case 1:
			//nolint:forcetypeassert
			return stunResp(
				&stun.XORMappedAddress{IP: net.ParseIP("203.0.113.10"), Port: 5000},
				&stun.OtherAddress{IP: net.ParseIP("127.0.0.1"), Port: srv.conn.LocalAddr().(*net.UDPAddr).Port},
			), true
		case 2:
			// Test II: respond → EpIndependent filtering
			return stunResp(), true
		default:
			return nil, false
		}
	})

	behavior, err := DiscoverNatFiltering(srv.Addr(), log)
	require.NoError(t, err)
	require.Equal(t, EpIndependent, behavior)
}

func TestDiscoverNatFiltering_AddrDependent(t *testing.T) {
	log := newTestLogger(t)

	srv := newTestStunServer(t)
	srv.SetHandler(func(call int, req *stun.Message) (*stun.Message, bool) {
		switch call {
		case 1:
			//nolint:forcetypeassert
			return stunResp(
				&stun.XORMappedAddress{IP: net.ParseIP("203.0.113.10"), Port: 5000},
				&stun.OtherAddress{IP: net.ParseIP("127.0.0.1"), Port: srv.conn.LocalAddr().(*net.UDPAddr).Port},
			), true

		case 2:
			return nil, false // timeout

		case 3:
			// Test III: respond → address dependent
			return stunResp(), true

		default:
			return nil, false
		}
	})

	start := time.Now()
	behavior, err := DiscoverNatFiltering(srv.Addr(), log)
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.Equal(t, AddrDependent, behavior)
	require.GreaterOrEqual(t, elapsed, defaultTimeout)
}

func TestDiscoverNatFiltering_AddrEpDependent(t *testing.T) {
	log := newTestLogger(t)

	srv := newTestStunServer(t)
	srv.SetHandler(
		func(call int, req *stun.Message) (*stun.Message, bool) {
			switch call {
			case 1:
				//nolint:forcetypeassert
				return stunResp(
					&stun.XORMappedAddress{IP: net.ParseIP("203.0.113.10"), Port: 5000},
					&stun.OtherAddress{IP: net.ParseIP("127.0.0.1"), Port: srv.conn.LocalAddr().(*net.UDPAddr).Port},
				), true

			case 2:
				return nil, false // timeout Test II
			case 3:
				return nil, false // timeout Test III → AddrEpDependent

			default:
				return nil, false
			}
		})

	start := time.Now()
	behavior, err := DiscoverNatFiltering(srv.Addr(), log)
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.Equal(t, AddrEpDependent, behavior)
	require.GreaterOrEqual(t, elapsed, 2*defaultTimeout)
}

func TestDiscoverNatFiltering_TestII_NonTimeoutErr(t *testing.T) {
	log := newTestLogger(t)

	srv := newTestStunServer(t)
	srv.SetHandler(func(call int, req *stun.Message) (*stun.Message, bool) {
		if call == 1 {
			//nolint:forcetypeassert
			return stunResp(
				&stun.XORMappedAddress{IP: net.ParseIP("203.0.113.10"), Port: 5000},
				&stun.OtherAddress{IP: net.ParseIP("127.0.0.1"), Port: srv.conn.LocalAddr().(*net.UDPAddr).Port}), true
		}
		if call == 2 {
			resp := &stun.Message{Raw: []byte("not-a-stun")}

			return resp, true
		}

		return nil, false
	})

	_, err := DiscoverNatFiltering(srv.Addr(), log)
	require.Error(t, err)
	require.ErrorIs(t, err, errDiscoverFiltering)
}
