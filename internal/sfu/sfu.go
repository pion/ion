package sfu

import (
	"errors"
	"sync"
)

var errPeerNotFound = errors.New("peer not found")

type SFU struct {
	id     string
	peers  map[string]Peer
	router *Router
	mu     sync.RWMutex
}

func (sfu *SFU) getPeer(peerId string) (Peer, error) {
	sfu.mu.RLock()
	defer sfu.mu.RUnlock()
	peer, ok := sfu.peers[peerId]
	if !ok {
		return nil, errPeerNotFound
	}
	return peer, nil
}

func (sfu *SFU) addPeer(peer Peer) {
	sfu.mu.Lock()
	defer sfu.mu.Unlock()
	sfu.peers[peer.ID()] = peer
}
