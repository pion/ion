// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package ice provides ICE, TURN, STUN services for Ion.
package ice

import (
	"context"
	"net"
	"time"
)

type (
	iceServerMode int
	networkType   int
)

const (
	Disabled iceServerMode = iota
	STUNOnlyMode
	TURNOnlyMode
	STUNAndTURNMode
)

const (
	NetworkUDP networkType = iota
	NetworkTCP
)

const dnsTimeout = 150 * time.Millisecond

const (
	DefaultPortRangeMin = 50000
	DefaultPortRangeMax = 52000
)

type ICEConfig struct {
	STUN STUNConfig `mapstructure:"stun"`
	TURN TURNConfig `mapstructure:"turn"`
}

type STUNConfig struct {
	UDPEndpoint string `mapstructure:"udp_endpoint"`
	TCPEndpoint string `mapstructure:"tcp_endpoint"`
	Enabled     bool   `mapstructure:"enabled"`
}

type TURNConfig struct {
	User         string    `mapstructure:"user"`
	UDPEndpoint  string    `mapstructure:"udp_endpoint"`
	TCPEndpoint  string    `mapstructure:"tcp_endpoint"`
	PublicIP     string    `mapstructure:"public_ip"`
	Realm        string    `mapstructure:"realm"`
	Auth         string    `mapstructure:"auth"`
	Password     string    `mapstructure:"password"`
	Secret       string    `mapstructure:"secret"`
	Address      string    `mapstructure:"address"`
	TLS          TLSConfig `mapstructure:"tls"`
	PortRangeMin uint16    `mapstructure:"port_range_min"`
	PortRangeMax uint16    `mapstructure:"port_range_max"`
	Enabled      bool
}

type TLSConfig struct {
	Endpoint string `mapstructure:"endpoint"`
	Cert     string `mapstructure:"cert"`
	Key      string `mapstructure:"key"`
	Version  uint16 `mapstructure:"version"`
}

func DefaultICEConfig() ICEConfig {
	return ICEConfig{
		STUN: STUNConfig{
			Enabled:     false,
			UDPEndpoint: ":3478",
			TCPEndpoint: ":3478",
		},
		TURN: TURNConfig{
			Enabled:      false,
			UDPEndpoint:  ":3478",
			TCPEndpoint:  ":3478",
			PublicIP:     "",
			Realm:        "ion",
			Address:      "0.0.0.0",
			PortRangeMin: DefaultPortRangeMin,
			PortRangeMax: DefaultPortRangeMax,
		},
	}
}

func (cfg *ICEConfig) ICEMode() iceServerMode {
	switch {
	case cfg.STUN.Enabled && cfg.TURN.Enabled:
		return STUNAndTURNMode
	case cfg.TURN.Enabled:
		return TURNOnlyMode
	case cfg.STUN.Enabled:
		return STUNOnlyMode
	default:
		return Disabled
	}
}

// STUNOnlyEndpoint returns STUN only udp/tcp endpoint for the configuration.
// Return empty string when no such endpoint exists.
func (cfg *ICEConfig) STUNOnlyEndpoint(network networkType) (string, error) {
	mode := cfg.ICEMode()
	if mode == TURNOnlyMode {
		return "", nil
	}

	var stunEp string
	if network == NetworkUDP {
		stunEp = cfg.STUN.UDPEndpoint
	} else {
		stunEp = cfg.STUN.TCPEndpoint
	}

	if mode == STUNOnlyMode || stunEp == "" {
		return stunEp, nil
	}
	// both stun and turn enabled and stun endpoint is NOT empty string
	var turnEp string
	if network == NetworkUDP {
		turnEp = cfg.TURN.UDPEndpoint
	} else {
		turnEp = cfg.TURN.TCPEndpoint
	}
	// check if we need to share
	addressSame, err := sameAddr(turnEp, stunEp)
	if err != nil {
		return "", err
	}
	if addressSame { // empty turn ep is considerred here
		return "", nil
	} else {
		return stunEp, nil
	}
}

// TURNOnlyEndpoint returns TURN only udp/tcp endpoint for the configuration.
// Return empty string when no such endpoint exists.
func (cfg *ICEConfig) TURNOnlyEndpoint(network networkType) (string, error) {
	mode := cfg.ICEMode()
	if mode == STUNOnlyMode {
		return "", nil
	}

	var turnEp string
	if network == NetworkUDP {
		turnEp = cfg.TURN.UDPEndpoint
	} else {
		turnEp = cfg.TURN.TCPEndpoint
	}

	if mode == STUNOnlyMode || turnEp == "" {
		return turnEp, nil
	}
	// both stun and turn enabled and turn endpoint is NOT empty string
	var stunEp string
	if network == NetworkUDP {
		stunEp = cfg.STUN.UDPEndpoint
	} else {
		stunEp = cfg.STUN.TCPEndpoint
	}
	// check if we need to share
	addressSame, err := sameAddr(stunEp, turnEp)
	if err != nil {
		return "", err
	}
	if addressSame { // empty stun ep is considerred here
		return "", nil
	} else {
		return turnEp, nil
	}
}

// TURNSTUNEndpoint returns endpoint shared by boths services for the configuration.
// Return empty string when no such endpoint exists.
func (cfg *ICEConfig) TURNSTUNEndpoint(network networkType) (string, error) {
	mode := cfg.ICEMode()
	if mode != STUNAndTURNMode {
		return "", nil
	}
	var turnEp string
	if network == NetworkUDP {
		turnEp = cfg.TURN.UDPEndpoint
	} else {
		turnEp = cfg.TURN.TCPEndpoint
	}
	var stunEp string
	if network == NetworkUDP {
		stunEp = cfg.STUN.UDPEndpoint
	} else {
		stunEp = cfg.STUN.TCPEndpoint
	}
	addressSame, err := sameAddr(stunEp, turnEp)
	if err != nil {
		return "", err
	}
	if addressSame { // Either empty endpoint goes to false branch
		return turnEp, nil
	} else {
		return "", nil
	}
}

func sameAddr(s1, s2 string) (bool, error) {
	if s1 == "" || s2 == "" {
		return false, nil
	}

	h1, p1, err := net.SplitHostPort(s1)
	if err != nil {
		return false, err
	}
	h2, p2, err := net.SplitHostPort(s2)
	if err != nil {
		return false, err
	}
	if p1 != p2 {
		return false, nil
	}
	if isWildcardHost(h1) || isWildcardHost(h2) {
		return true, nil
	}

	return hostsCollide(h1, h2)
}

func hostsCollide(h1, h2 string) (bool, error) {
	// If both literal IPs, compare directly.
	if ip1, ip2 := net.ParseIP(h1), net.ParseIP(h2); ip1 != nil && ip2 != nil {
		return ip1.Equal(ip2), nil
	}
	// Otherwise do DNS-aware overlap check.
	return dnsOverlap(h1, h2)
}

func dnsOverlap(h1, h2 string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()

	ips1, err := net.DefaultResolver.LookupIPAddr(ctx, h1)
	if err != nil {
		return false, err
	}
	ips2, err := net.DefaultResolver.LookupIPAddr(ctx, h2)
	if err != nil {
		return false, err
	}

	set := make(map[string]struct{}, len(ips1))
	for _, a := range ips1 {
		set[a.IP.String()] = struct{}{}
	}
	for _, b := range ips2 {
		if _, ok := set[b.IP.String()]; ok {
			return true, nil
		}
	}

	return false, nil
}

func isWildcardHost(h string) bool {
	return h == "" || h == "0.0.0.0" || h == "::"
}
