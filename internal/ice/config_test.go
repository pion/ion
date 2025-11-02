package ice

import (
	"testing"

	"github.com/stretchr/testify/require"
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
			cfg:  ICEConfig{STUN: STUNConfig{Enabled: true, UDPEndpoint: ":3478"}},
			want: ":3478",
		},
		{
			name: "TURN only ⇒ empty",
			cfg:  ICEConfig{TURN: TURNConfig{Enabled: true, UDPEndpoint: ":3478"}},
			want: "",
		},
		{
			name: "Both enabled, same UDP endpoint ⇒ empty",
			cfg: ICEConfig{
				STUN: STUNConfig{Enabled: true, UDPEndpoint: ":3478"},
				TURN: TURNConfig{Enabled: true, UDPEndpoint: ":3478"},
			},
			want: "",
		},
		{
			name: "Both enabled, different UDP endpoints ⇒ return STUN endpoint",
			cfg: ICEConfig{
				STUN: STUNConfig{Enabled: true, UDPEndpoint: ":3479"},
				TURN: TURNConfig{Enabled: true, UDPEndpoint: ":3478"},
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
		STUN: STUNConfig{Enabled: true, TCPEndpoint: ":3478"},
	}
	got, err := cfg.STUNOnlyEndpoint(NetworkTCP)
	require.NoError(t, err)
	require.Equal(t, ":3478", got)
}

func TestTURNOnlyEndpoint_UDP(t *testing.T) {
	tests := []struct {
		name string
		want string
		cfg  ICEConfig
	}{
		{
			name: "TURN only returns its UDP endpoint",
			cfg:  ICEConfig{TURN: TURNConfig{Enabled: true, UDPEndpoint: ":3478"}},
			want: ":3478",
		},
		{
			name: "STUN only ⇒ empty",
			cfg: ICEConfig{
				STUN: STUNConfig{Enabled: true, UDPEndpoint: ":3478"},
			},
			want: "",
		},
		{
			name: "Both enabled, same UDP endpoint ⇒ empty",
			cfg: ICEConfig{
				STUN: STUNConfig{Enabled: true, UDPEndpoint: ":3478"},
				TURN: TURNConfig{Enabled: true, UDPEndpoint: ":3478"},
			},
			want: "",
		},
		{
			name: "Both enabled, different UDP endpoints ⇒ return TURN endpoint",
			cfg: ICEConfig{
				STUN: STUNConfig{Enabled: true, UDPEndpoint: ":3479"},
				TURN: TURNConfig{Enabled: true, UDPEndpoint: ":3478"},
			},
			want: ":3478",
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
		TURN: TURNConfig{Enabled: true, TCPEndpoint: ":3478"},
	}
	got, err := cfg.TURNOnlyEndpoint(NetworkTCP)
	require.NoError(t, err)
	require.Equal(t, ":3478", got)
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
				STUN: STUNConfig{Enabled: true, UDPEndpoint: ":3478"},
				TURN: TURNConfig{Enabled: true, UDPEndpoint: ":3478"},
			},
			want: ":3478",
		},
		{
			name: "Both enabled, different endpoints ⇒ empty",
			cfg: ICEConfig{
				STUN: STUNConfig{Enabled: true, UDPEndpoint: ":3479"},
				TURN: TURNConfig{Enabled: true, UDPEndpoint: ":3478"},
			},
			want: "",
		},
		{
			name: "Not both enabled ⇒ empty",
			cfg: ICEConfig{
				STUN: STUNConfig{Enabled: true, UDPEndpoint: ":3478"},
				TURN: TURNConfig{Enabled: false, UDPEndpoint: ":3478"},
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
				TURN: TURNConfig{Enabled: true, UDPEndpoint: ":3478"},
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
		{"bare port equal", ":3478", ":3478", true, false},
		{"ipv4 equal", "127.0.0.1:3478", "127.0.0.1:3478", true, false},
		{"ipv6 equal", "[::1]:3478", "[::1]:3478", true, false},
		{"different port", "127.0.0.1:3478", "127.0.0.1:3479", false, false},
		{"different host", "127.0.0.1:3478", "127.0.0.2:3478", false, false},
		{"hostname vs ip", "localhost:3478", "127.0.0.1:3478", true, false},
		{"zero vs bare", "0.0.0.0:3478", ":3478", true, false},
		{"missing port", "127.0.0.1", ":3478", false, true},
		{"malformed", ";3478", ":3478", false, true},
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
