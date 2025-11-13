// SPDX-FileCopyrightText: 2025 The Pion community
// SPDX-License-Identifier: MIT
package ice

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	realmIon     = "ion"
	authStatic   = "static"
	defaultEP    = ":3478"
	defaultTLSEp = "127.0.0.1:5349"
)

func TestICEMode(t *testing.T) {
	cases := []struct {
		stun, turn bool
		want       iceServerMode
	}{
		{false, false, Disabled},
		{true, false, STUNOnlyMode},
		{false, true, TURNOnlyMode},
		{true, true, STUNAndTURNMode},
	}
	for i, tc := range cases {
		cfg := DefaultICEConfig()
		cfg.STUN.Enabled = tc.stun
		cfg.TURN.Enabled = tc.turn
		require.Equalf(t, tc.want, cfg.ICEMode(), "case %d", i)
	}
}

func TestSTUNOnlyEndpoint_UDP(t *testing.T) {
	tests := []struct {
		name    string
		want    string
		cfg     ICEConfig
		wantErr bool
	}{
		{
			name: "STUN only returns its UDP endpoint",
			cfg:  ICEConfig{STUN: STUNConfig{Enabled: true, UDPEndpoint: defaultEP}},
			want: defaultEP,
		},
		{
			name: "TURN only ⇒ empty",
			cfg:  ICEConfig{TURN: TURNConfig{Enabled: true, UDPEndpoint: defaultEP}},
			want: "",
		},
		{
			name: "Both enabled, same UDP endpoint ⇒ empty",
			cfg: ICEConfig{
				STUN: STUNConfig{Enabled: true, UDPEndpoint: defaultEP},
				TURN: TURNConfig{Enabled: true, UDPEndpoint: defaultEP},
			},
			want: "",
		},
		{
			name: "Both enabled, different UDP endpoints ⇒ return STUN endpoint",
			cfg: ICEConfig{
				STUN: STUNConfig{Enabled: true, UDPEndpoint: ":3479"},
				TURN: TURNConfig{Enabled: true, UDPEndpoint: defaultEP},
			},
			want: ":3479",
		},
		{
			name: "Empty STUN endpoint ⇒ empty",
			cfg:  ICEConfig{STUN: STUNConfig{Enabled: true, UDPEndpoint: ""}},
			want: "",
		},
		{
			name: "IPv6 bracket forms, different ports ⇒ return STUN endpoint",
			cfg: ICEConfig{
				STUN: STUNConfig{Enabled: true, UDPEndpoint: "[::1]:3479"},
				TURN: TURNConfig{Enabled: true, UDPEndpoint: "[::1]:3478"},
			},
			want: "[::1]:3479",
		},
		{
			name: "Hostname vs IP, same port but different hosts ⇒ return empty",
			cfg: ICEConfig{
				STUN: STUNConfig{Enabled: true, UDPEndpoint: "localhost:3478"},
				TURN: TURNConfig{Enabled: true, UDPEndpoint: "127.0.0.1:3478"},
			},
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.cfg.STUNOnlyEndpoint(NetworkUDP)
			if tc.wantErr {
				require.Error(t, err)

				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestSTUNOnlyEndpoint_TCP(t *testing.T) {
	cfg := ICEConfig{
		STUN: STUNConfig{Enabled: true, TCPEndpoint: defaultEP},
	}
	got, err := cfg.STUNOnlyEndpoint(NetworkTCP)
	require.NoError(t, err)
	require.Equal(t, defaultEP, got)
}

func TestTURNOnlyEndpoint_UDP(t *testing.T) {
	tests := []struct {
		name string
		want string
		cfg  ICEConfig
	}{
		{
			name: "TURN only returns its UDP endpoint",
			cfg:  ICEConfig{TURN: TURNConfig{Enabled: true, UDPEndpoint: defaultEP}},
			want: defaultEP,
		},
		{
			name: "STUN only ⇒ empty",
			cfg: ICEConfig{
				STUN: STUNConfig{Enabled: true, UDPEndpoint: defaultEP},
			},
			want: "",
		},
		{
			name: "Both enabled, same UDP endpoint ⇒ empty",
			cfg: ICEConfig{
				STUN: STUNConfig{Enabled: true, UDPEndpoint: defaultEP},
				TURN: TURNConfig{Enabled: true, UDPEndpoint: defaultEP},
			},
			want: "",
		},
		{
			name: "Both enabled, different UDP endpoints ⇒ return TURN endpoint",
			cfg: ICEConfig{
				STUN: STUNConfig{Enabled: true, UDPEndpoint: ":3479"},
				TURN: TURNConfig{Enabled: true, UDPEndpoint: defaultEP},
			},
			want: defaultEP,
		},
		{
			name: "Empty TURN endpoint ⇒ empty",
			cfg:  ICEConfig{TURN: TURNConfig{Enabled: true, UDPEndpoint: ""}},
			want: "",
		},
		{
			name: "IPv6 bracket forms, different hosts same port ⇒ return empty",
			cfg: ICEConfig{
				STUN: STUNConfig{Enabled: true, UDPEndpoint: "[::1]:3478"},
				TURN: TURNConfig{Enabled: true, UDPEndpoint: "[::]:3478"},
			},
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.cfg.TURNOnlyEndpoint(NetworkUDP)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestTURNOnlyEndpoint_TCP(t *testing.T) {
	cfg := ICEConfig{
		TURN: TURNConfig{Enabled: true, TCPEndpoint: defaultEP},
	}
	got, err := cfg.TURNOnlyEndpoint(NetworkTCP)
	require.NoError(t, err)
	require.Equal(t, defaultEP, got)
}

func TestTURNSTUNEndpoint_UDP(t *testing.T) {
	tests := []struct {
		name string
		want string
		cfg  ICEConfig
	}{
		{
			name: "Both enabled, same endpoint ⇒ shared returned",
			cfg: ICEConfig{
				STUN: STUNConfig{Enabled: true, UDPEndpoint: defaultEP},
				TURN: TURNConfig{Enabled: true, UDPEndpoint: defaultEP},
			},
			want: defaultEP,
		},
		{
			name: "Both enabled, different endpoints ⇒ empty",
			cfg: ICEConfig{
				STUN: STUNConfig{Enabled: true, UDPEndpoint: ":3479"},
				TURN: TURNConfig{Enabled: true, UDPEndpoint: defaultEP},
			},
			want: "",
		},
		{
			name: "Not both enabled ⇒ empty",
			cfg: ICEConfig{
				STUN: STUNConfig{Enabled: true, UDPEndpoint: defaultEP},
				TURN: TURNConfig{Enabled: false, UDPEndpoint: defaultEP},
			},
			want: "",
		},
		{
			name: "IPv6 shared ⇒ shared returned",
			cfg: ICEConfig{
				STUN: STUNConfig{Enabled: true, UDPEndpoint: "[::1]:3478"},
				TURN: TURNConfig{Enabled: true, UDPEndpoint: "[::1]:3478"},
			},
			want: "[::1]:3478",
		},
		{
			name: "Hostname vs IP same port ⇒  shared ⇒ TURN's endpoint",
			cfg: ICEConfig{
				STUN: STUNConfig{Enabled: true, UDPEndpoint: "localhost:3478"},
				TURN: TURNConfig{Enabled: true, UDPEndpoint: "127.0.0.1:3478"},
			},
			want: "127.0.0.1:3478",
		},
		{
			name: "One endpoint empty ⇒ empty",
			cfg: ICEConfig{
				STUN: STUNConfig{Enabled: true, UDPEndpoint: ""},
				TURN: TURNConfig{Enabled: true, UDPEndpoint: defaultEP},
			},
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.cfg.TURNSTUNEndpoint(NetworkUDP)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestTURNSTUNEndpoint_TCP(t *testing.T) {
	cfg := ICEConfig{
		STUN: STUNConfig{Enabled: true, TCPEndpoint: "[::1]:3478"},
		TURN: TURNConfig{Enabled: true, TCPEndpoint: "[::1]:3478"},
	}
	got, err := cfg.TURNSTUNEndpoint(NetworkTCP)
	require.NoError(t, err)
	require.Equal(t, "[::1]:3478", got)
}

func TestSameAddr(t *testing.T) {
	tests := []struct {
		name     string
		a, b     string
		wantSame bool
		wantErr  bool
	}{
		{"bare port equal", defaultEP, defaultEP, true, false},
		{"ipv4 equal", "127.0.0.1:3478", "127.0.0.1:3478", true, false},
		{"ipv6 equal", "[::1]:3478", "[::1]:3478", true, false},
		{"different port", "127.0.0.1:3478", "127.0.0.1:3479", false, false},
		{"different host", "127.0.0.1:3478", "127.0.0.2:3478", false, false},
		{"hostname vs ip", "localhost:3478", "127.0.0.1:3478", true, false},
		{"zero vs bare", "0.0.0.0:3478", defaultEP, true, false},
		{"missing port", "127.0.0.1", defaultEP, false, true},
		{"malformed", ";3478", defaultEP, false, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sameAddr(tc.a, tc.b)
			if tc.wantErr {
				require.Error(t, err)

				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantSame, got)
		})
	}
}

func TestICEConfigValidate(t *testing.T) {
	tests := []struct {
		err  error
		name string
		cfg  ICEConfig
	}{
		{
			name: "Disabled OK",
			cfg:  DefaultICEConfig(),
			err:  nil,
		},
		{
			name: "STUN enabled but empty endpoints",
			cfg: func() ICEConfig {
				cfg := DefaultICEConfig()
				cfg.STUN.Enabled = true
				cfg.STUN.UDPEndpoint = ""
				cfg.STUN.TCPEndpoint = ""

				return cfg
			}(),
			err: errEmptySTUNEndpoint,
		},
		{
			name: "TURN enabled but all endpoints empty",
			cfg: func() ICEConfig {
				cfg := DefaultICEConfig()
				cfg.TURN.Enabled = true
				cfg.TURN.UDPEndpoint = ""
				cfg.TURN.TCPEndpoint = ""
				cfg.TURN.TLS.Endpoint = ""
				cfg.TURN.Realm = realmIon
				cfg.TURN.Auth = authStatic
				cfg.TURN.User = "u"
				cfg.TURN.Password = "p"

				return cfg
			}(),
			err: errEmptyTURNEndpoint,
		},
		{
			name: "TURN empty realm",
			cfg: func() ICEConfig {
				cfg := DefaultICEConfig()
				cfg.TURN.Enabled = true
				cfg.TURN.UDPEndpoint = defaultEP
				cfg.TURN.Realm = " "
				cfg.TURN.Auth = authStatic
				cfg.TURN.User = "u"
				cfg.TURN.Password = "p"

				return cfg
			}(),
			err: errEmptyRealm,
		},
		{
			name: "TURN invalid port range (min=0 max>0)",
			cfg: func() ICEConfig {
				cfg := DefaultICEConfig()
				cfg.TURN.Enabled = true
				cfg.TURN.UDPEndpoint = defaultEP
				cfg.TURN.Realm = realmIon
				cfg.TURN.Auth = authStatic
				cfg.TURN.User = "u"
				cfg.TURN.Password = "p"
				cfg.TURN.PortRangeMin = 0
				cfg.TURN.PortRangeMax = 60000

				return cfg
			}(),
			err: errInvalidPortRange,
		},
		{
			name: "TURN static auth missing user",
			cfg: func() ICEConfig {
				cfg := DefaultICEConfig()
				cfg.TURN.Enabled = true
				cfg.TURN.UDPEndpoint = defaultEP
				cfg.TURN.Realm = realmIon
				cfg.TURN.Auth = authStatic
				cfg.TURN.User = ""
				cfg.TURN.Password = "p"

				return cfg
			}(),
			err: errEmptyTURNUserPwd,
		},
		{
			name: "TURN long-term missing secret",
			cfg: func() ICEConfig {
				cfg := DefaultICEConfig()
				cfg.TURN.Enabled = true
				cfg.TURN.UDPEndpoint = defaultEP
				cfg.TURN.Realm = realmIon
				cfg.TURN.Auth = "long-term"
				cfg.TURN.Secret = ""

				return cfg
			}(),
			err: errEmptyTURNToken,
		},
		{
			name: "TURN TLS missing cert/key",
			cfg: func() ICEConfig {
				cfg := DefaultICEConfig()
				cfg.TURN.Enabled = true
				cfg.TURN.UDPEndpoint = defaultEP
				cfg.TURN.Realm = realmIon
				cfg.TURN.Auth = authStatic
				cfg.TURN.User = "u"
				cfg.TURN.Password = "p"
				cfg.TURN.TLS.Endpoint = defaultTLSEp // enable TLS mode

				return cfg
			}(),
			err: errEmptyTLSCertKey,
		},
		{
			name: "TURN TLS invalid version",
			cfg: func() ICEConfig {
				cfg := DefaultICEConfig()
				cfg.TURN.Enabled = true
				cfg.TURN.UDPEndpoint = defaultEP
				cfg.TURN.Realm = realmIon
				cfg.TURN.Auth = authStatic
				cfg.TURN.User = "u"
				cfg.TURN.Password = "p"
				cfg.TURN.TLS.Endpoint = defaultTLSEp
				cfg.TURN.TLS.Cert = "/tmp/cert.pem"
				cfg.TURN.TLS.Key = "/tmp/key.pem"
				cfg.TURN.TLS.Version = "TLS15"

				return cfg
			}(),
			err: errInvalidTLSVersion,
		},
		{
			name: "Valid TURN + STUN + TLS config",
			cfg: func() ICEConfig {
				cfg := DefaultICEConfig()
				cfg.STUN.Enabled = true
				cfg.STUN.UDPEndpoint = defaultEP
				cfg.STUN.TCPEndpoint = defaultEP
				cfg.TURN.Enabled = true
				cfg.TURN.UDPEndpoint = defaultEP
				cfg.TURN.TCPEndpoint = defaultEP
				cfg.TURN.Realm = realmIon
				cfg.TURN.Auth = authStatic
				cfg.TURN.User = "u"
				cfg.TURN.Password = "p"
				cfg.TURN.TLS.Endpoint = defaultTLSEp
				cfg.TURN.TLS.Cert = "/tmp/cert.pem"
				cfg.TURN.TLS.Key = "/tmp/key.pem"
				cfg.TURN.TLS.Version = "TLS12"

				return cfg
			}(),
			err: nil,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.cfg.Validate()

			if testCase.err == nil {
				require.NoError(t, err, "expected success but got error")
			} else {
				require.ErrorIs(t, err, testCase.err, "wrong error returned")
			}
		})
	}
}
