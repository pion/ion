// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/pion/stun/v3"
)

const (
	defaultStunAddr = "stun.voipgate.com:3478"
	defaultTimeout  = 1 * time.Second
	bufferSize      = 1024
)

type stunServerConn struct {
	conn        net.PacketConn
	LocalAddr   net.Addr
	RemoteAddr  *net.UDPAddr
	OtherAddr   *net.UDPAddr
	messageChan chan *stun.Message
}

type (
	natBehavior int
)

const (
	NoNAT natBehavior = iota
	EpIndependent
	AddrDependent
	AddrEpDependent
)

var (
	errConnectStun       = errors.New("cannot connect to stun server")
	errRoundTrip         = errors.New("cannot make round trip to stun server")
	errDiscoverMapping   = errors.New("error discovering nat mapping")
	errDiscoverFiltering = errors.New("error discovering nat filtering")
	errDiscoverLocal     = errors.New("cannot discover local IP")
	errNoLocalIPFound    = errors.New("no valid local ip address found")
	errResponseMessage   = errors.New("error reading from response message channel")
	errTimedOut          = errors.New("timed out waiting for response")
	errNoOtherAddress    = errors.New("no OTHER-ADDRESS in message")
)

func (c *stunServerConn) Close() error {
	return c.conn.Close()
}

// Utility functions for NAT detection, local network discovery.

// DiscoverLocalIP returns IP address for local interface.
func DiscoverLocalIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", fmt.Errorf("%w: %w", errDiscoverLocal, err)
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback then display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}

	return "", errNoLocalIPFound
}

// DiscoverNatMapping determines NAT mapping under RFC5780: 4.3.
// Adapted from pion/stun.
func DiscoverNatMapping(stunAddr string, log *slog.Logger) (natBehavior, error) { //nolint:cyclop
	if stunAddr == "" {
		stunAddr = defaultStunAddr
	}
	log.Info("Discovering NAT mapping", "stunAddr", stunAddr)

	mapTestConn, err := connect(stunAddr, log)
	defer func() {
		if mapTestConn != nil {
			if cerr := mapTestConn.Close(); cerr != nil {
				log.Warn(cerr.Error())
			}
		}
	}()
	if err != nil {
		return AddrEpDependent, fmt.Errorf("%w: %w", errDiscoverMapping, err)
	}

	localAddr, err := DiscoverLocalIP()
	if err != nil {
		return AddrEpDependent, fmt.Errorf("%w: %w", errDiscoverMapping, err)
	}

	// Test I: Regular binding request
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	resp, err := mapTestConn.roundTrip(request, mapTestConn.RemoteAddr, log)
	if err != nil {
		return AddrEpDependent, fmt.Errorf("%w: %w", errDiscoverMapping, err)
	}

	// Parse response message for XOR-MAPPED-ADDRESS and make sure OTHER-ADDRESS valid
	resps1 := parse(resp, log)
	if resps1.xorAddr == nil || resps1.otherAddr == nil {
		return AddrEpDependent, fmt.Errorf("%w: %w", errDiscoverMapping, errNoOtherAddress)
	}
	addr, err := net.ResolveUDPAddr("udp4", resps1.otherAddr.String())
	if err != nil {
		return AddrEpDependent, fmt.Errorf("%w: %w", errDiscoverMapping, err)
	}
	mapTestConn.OtherAddr = addr
	log.Debug("", "Received XOR-MAPPED-ADDRESS", resps1.xorAddr)

	// Assert mapping behavior
	if resps1.xorAddr.IP.String() == localAddr {
		log.Info("NAT mapping behavior: endpoint independent (no NAT)")

		return NoNAT, nil
	}

	// Test II: Send binding request to the other address but primary port
	log.Info("Mapping Test II: Send binding request to the other address but primary port")
	oaddr := *mapTestConn.OtherAddr
	oaddr.Port = mapTestConn.RemoteAddr.Port
	resp, err = mapTestConn.roundTrip(request, &oaddr, log)
	if err != nil {
		return AddrEpDependent, fmt.Errorf("%w: %w", errDiscoverMapping, err)
	}

	// Assert mapping behavior
	resps2 := parse(resp, log)
	log.Debug("", "Received XOR-MAPPED-ADDRESS", resps2.xorAddr)
	if resps2.xorAddr.String() == resps1.xorAddr.String() {
		log.Info("NAT mapping behavior: endpoint independent")

		return EpIndependent, nil
	}

	// Test III: Send binding request to the other address and port
	log.Debug("Mapping Test III: Send binding request to the other address and port")
	resp, err = mapTestConn.roundTrip(request, mapTestConn.OtherAddr, log)
	if err != nil {
		return AddrEpDependent, fmt.Errorf("%w: %w", errDiscoverMapping, err)
	}

	// Assert mapping behavior
	resps3 := parse(resp, log)
	log.Debug("", "Received XOR-MAPPED-ADDRESS", resps3.xorAddr)
	if resps3.xorAddr.String() == resps2.xorAddr.String() {
		log.Warn("NAT mapping behavior: address dependent")

		return AddrDependent, nil
	} else {
		log.Warn("NAT mapping behavior: address and port dependent")

		return AddrEpDependent, nil
	}
}

// DiscoverNatFiltering determines NAT filtering behavior under RFC5780: 4.4.
// Adapted from pion/stun.
func DiscoverNatFiltering(stunAddr string, log *slog.Logger) (natBehavior, error) { //nolint:cyclop
	if stunAddr == "" {
		stunAddr = defaultStunAddr
	}
	log.Info("Discovering NAT filtering", "stunAddr", stunAddr)

	mapTestConn, err := connect(stunAddr, log)
	defer func() {
		if mapTestConn != nil {
			if cerr := mapTestConn.Close(); cerr != nil {
				log.Warn(cerr.Error())
			}
		}
	}()
	if err != nil {
		return AddrEpDependent, fmt.Errorf("%w: %w", errDiscoverFiltering, err)
	}

	// Test I: Regular binding request
	log.Info("Filtering Test I: Regular binding request")
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	resp, err := mapTestConn.roundTrip(request, mapTestConn.RemoteAddr, log)
	if err != nil || errors.Is(err, errTimedOut) {
		return AddrEpDependent, fmt.Errorf("%w: %w", errDiscoverFiltering, err)
	}
	resps := parse(resp, log)
	if resps.xorAddr == nil || resps.otherAddr == nil {
		return AddrEpDependent, fmt.Errorf("%w: %w", errDiscoverFiltering, errNoOtherAddress)
	}
	addr, err := net.ResolveUDPAddr("udp4", resps.otherAddr.String())
	if err != nil {
		return AddrEpDependent, fmt.Errorf("%w: %w", errDiscoverFiltering, err)
	}
	mapTestConn.OtherAddr = addr

	// Test II: Request to change both IP and port
	log.Info("Filtering Test II: Request to change both IP and port")
	request = stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	request.Add(stun.AttrChangeRequest, []byte{0x00, 0x00, 0x00, 0x06})

	resp, err = mapTestConn.roundTrip(request, mapTestConn.RemoteAddr, log)
	if err == nil {
		parse(resp, log) // just to print out the resp
		log.Info("NAT filtering behavior: endpoint independent")

		return EpIndependent, nil
	} else if !errors.Is(err, errTimedOut) {
		return AddrEpDependent, fmt.Errorf("%w: %w", errDiscoverFiltering, err) // something else went wrong
	}

	// Test III: Request to change port only
	log.Info("Filtering Test III: Request to change port only")
	request = stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	request.Add(stun.AttrChangeRequest, []byte{0x00, 0x00, 0x00, 0x02})

	resp, err = mapTestConn.roundTrip(request, mapTestConn.RemoteAddr, log)
	switch {
	case err == nil:
		{
			parse(resp, log)
			log.Warn("=> NAT filtering behavior: address dependent")

			return AddrDependent, nil
		}
	case errors.Is(err, errTimedOut):
		{
			log.Warn("=> NAT filtering behavior: address and port dependent")

			return AddrEpDependent, nil
		}
	default:
		return AddrEpDependent, fmt.Errorf("%w: %w", errDiscoverFiltering, err)
	}
}

// Given an address string, returns a StunServerConn.
func connect(addrStr string, log *slog.Logger) (*stunServerConn, error) {
	log.Debug("Connecting to STUN server", "server", addrStr)
	addr, err := net.ResolveUDPAddr("udp4", addrStr)
	if err != nil {
		return nil, fmt.Errorf("%w: addr: %v,%w", errConnectStun, addrStr, err)
	}

	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, fmt.Errorf("%w: addr: %v, %w", errConnectStun, addrStr, err)
	}
	log.Debug("", "Local address", c.LocalAddr())
	log.Debug("", "Remote address", addr.String())

	mChan := listen(c, log)

	return &stunServerConn{
		conn:        c,
		LocalAddr:   c.LocalAddr(),
		RemoteAddr:  addr,
		messageChan: mChan,
	}, nil
}

// Send request and wait for response or timeout.
// Adapted from pion/stun.
func (c *stunServerConn) roundTrip(msg *stun.Message, addr net.Addr, log *slog.Logger) (*stun.Message, error) {
	_ = msg.NewTransactionID()
	log.Debug(msg.String())
	_, err := c.conn.WriteTo(msg.Raw, addr)
	if err != nil {
		return nil, fmt.Errorf("%w: addr: %v, %w", errRoundTrip, addr.String(), err)
	}

	// Wait for response or timeout
	select {
	case m, ok := <-c.messageChan:
		if !ok {
			return nil, errResponseMessage
		}

		return m, nil
	case <-time.After(defaultTimeout):
		log.Error("Timed out waiting for response from server", "address", addr)

		return nil, fmt.Errorf("%w: addr:%v, %w", errRoundTrip, addr, errTimedOut)
	}
}

// taken from https://github.com/pion/stun/blob/master/cmd/stun-traversal/main.go
func listen(conn *net.UDPConn, log *slog.Logger) (messages chan *stun.Message) {
	messages = make(chan *stun.Message)
	go func() {
		for {
			buf := make([]byte, bufferSize)

			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				close(messages)

				return
			}
			buf = buf[:n]

			m := new(stun.Message)
			m.Raw = buf
			err = m.Decode()
			if err != nil {
				log.Error(err.Error())
				close(messages)

				return
			}

			messages <- m
		}
	}()

	return
}

// Parse a STUN message.
// Adapted from pion/stun.
func parse(msg *stun.Message, log *slog.Logger) (ret struct {
	xorAddr    *stun.XORMappedAddress
	otherAddr  *stun.OtherAddress
	respOrigin *stun.ResponseOrigin
	mappedAddr *stun.MappedAddress
	software   *stun.Software
},
) {
	ret.mappedAddr = &stun.MappedAddress{}
	ret.xorAddr = &stun.XORMappedAddress{}
	ret.respOrigin = &stun.ResponseOrigin{}
	ret.otherAddr = &stun.OtherAddress{}
	ret.software = &stun.Software{}
	if ret.xorAddr.GetFrom(msg) != nil {
		ret.xorAddr = nil
	}
	if ret.otherAddr.GetFrom(msg) != nil {
		ret.otherAddr = nil
	}
	if ret.respOrigin.GetFrom(msg) != nil {
		ret.respOrigin = nil
	}
	if ret.mappedAddr.GetFrom(msg) != nil {
		ret.mappedAddr = nil
	}
	if ret.software.GetFrom(msg) != nil {
		ret.software = nil
	}
	for _, attr := range msg.Attributes {
		switch attr.Type {
		case
			stun.AttrXORMappedAddress,
			stun.AttrOtherAddress,
			stun.AttrResponseOrigin,
			stun.AttrMappedAddress,
			stun.AttrSoftware:
			break //nolint:staticcheck
		default:
			log.Debug(fmt.Sprintf("\t%v (l=%v)", attr, attr.Length))
		}
	}

	return ret
}
