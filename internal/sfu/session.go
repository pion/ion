package sfu

import (
	"sync"
)

type Session interface {
	ID() string
	Peers() []Peer
	AddPeer(peer Peer)
	RemovePeer(peer Peer)
}

type SessionLocal struct {
	id    string
	peers map[string]Peer
	mu    sync.RWMutex
}
