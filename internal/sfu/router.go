// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sfu

import "sync"

// Subscription represents a subscription to a peer with peerID and tracks with trackID
type Subscription struct {
	peerID  string
	trackID []string
}

type Router interface {
	Subscribe(peer Peer, sub *Subscription)
	Unsubscribe(peer Peer, sub *Subscription)
}

type DefaultRouter struct {
	sessionID string

	mu            sync.RWMutex
	subscriptions map[string]*Subscription // peerID -> subscription
}
