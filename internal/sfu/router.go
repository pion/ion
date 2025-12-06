// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sfu

import (
	"log/slog"
	"sync"

	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"
)

type TrackKey struct {
	peerID  string
	trackID string
}

// Subscription represents a subscription to a peer with peerID and tracks with trackID
type Subscription struct {
	PubPeer  Peer     // the upstream peer whose tracks we subscribe to
	TrackIDs []string // empty = all tracks
}

type Router interface {
	Subscribe(peer Peer, sub *Subscription)
	Unsubscribe(peer Peer, sub *Subscription)
}

type sessionRouter struct {
	sessionID string

	logger        *slog.Logger
	mu            sync.RWMutex
	subscriptions map[string]*Subscription
	trackRouters  map[TrackKey]*trackRouter
}

func newSessionRouter(sessionID string, logger *slog.Logger) *sessionRouter {
	logger = logger.With("session_id", sessionID)
	return &sessionRouter{
		sessionID:     sessionID,
		logger:        logger,
		mu:            sync.RWMutex{},
		subscriptions: make(map[string]*Subscription),
		trackRouters:  make(map[TrackKey]*trackRouter),
	}
}

func (sr *sessionRouter) Close() {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	for peerID := range sr.subscriptions {
		sr.Unsubscribe(peerID)
	}
}

func (sr *sessionRouter) Subscribe(subPeer Peer, sub *Subscription) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.logger.Debug("Subscribe", "subscriber_id", subPeer.ID(), "publisher_id", sub.PubPeer.ID(), "track_ids", sub.TrackIDs)

	subID := subPeer.ID()
	sr.subscriptions[subID] = sub
	pubTracks := sub.PubPeer.Publisher().GetTracks()
	for _, trackID := range sub.TrackIDs {
		track := pubTracks[trackID]
		if track == nil {
			sr.logger.Error("Track not found", "track_id", trackID)
			continue
		}
		trackKey := TrackKey{peerID: sub.PubPeer.ID(), trackID: trackID}
		if sr.trackRouters[trackKey] == nil {
			sr.trackRouters[trackKey] = newTrackRouter(trackKey, track, sub.PubPeer, sr.logger)
		}
		sr.trackRouters[trackKey].AddSink(subPeer)
	}
	subPeer.Subscriber().Renegotiate(subPeer)
}

func (sr *sessionRouter) Unsubscribe(peerID string) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	delete(sr.subscriptions, peerID)
}

// trackRouter represents a router for one publisher track
type trackRouter struct {
	trackKey      TrackKey
	pubPeer       Peer
	logger        *slog.Logger
	track         *webrtc.TrackRemote
	receiver      *webrtc.RTPReceiver
	mu            sync.RWMutex
	subscriptions map[string]*Subscription
	sinks         map[string]*sink
	stopCh        chan struct{}
}

type sink struct {
	peerID     string
	localTrack *webrtc.TrackLocalStaticRTP
	sender     *webrtc.RTPSender
}

func newTrackRouter(trackKey TrackKey, track *webrtc.TrackRemote, pubPeer Peer, logger *slog.Logger) *trackRouter {
	tr := &trackRouter{
		trackKey:      trackKey,
		pubPeer:       pubPeer,
		logger:        logger,
		track:         track,
		mu:            sync.RWMutex{},
		subscriptions: make(map[string]*Subscription),
		sinks:         make(map[string]*sink),
		stopCh:        make(chan struct{}),
	}
	go tr.forward()
	return tr
}

func (tr *trackRouter) AddSink(subPeer Peer) {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	subID := subPeer.ID()
	localTrack, err := webrtc.NewTrackLocalStaticRTP(tr.track.Codec().RTPCodecCapability, tr.track.ID(), tr.track.StreamID())
	if err != nil {
		tr.logger.Error("NewTrackLocalStaticRTP failed", "error", err)
		return
	}
	tr.logger.Debug("AddOutgoingTrack", "subscriber_id", subID, "track_id", tr.track.ID(), "kind", tr.track.Kind())
	sender, err := subPeer.Subscriber().AddOutgoingTrack(localTrack)
	if err != nil {
		tr.logger.Error("AddOutgoingTrack failed",
			"subscriber_peer_id", subID,
			"error", err)
		return
	}

	tr.sinks[subID] = &sink{
		peerID:     subID,
		localTrack: localTrack,
		sender:     sender,
	}
	if tr.track.Kind() == webrtc.RTPCodecTypeVideo {
		tr.pubPeer.Publisher().pc.WriteRTCP(
			[]rtcp.Packet{
				&rtcp.PictureLossIndication{MediaSSRC: uint32(tr.track.SSRC())},
			},
		)
	}
}

func (tr *trackRouter) forward() {
	buf := make([]byte, 1500)
	for {
		select {
		case <-tr.stopCh:
			return
		default:
		}

		n, _, readErr := tr.track.Read(buf)
		if readErr != nil {
			tr.logger.Error("track read failed", "error", readErr)
			return
		}

		pk := buf[:n]

		tr.mu.RLock()
		for _, s := range tr.sinks {
			if _, writeErr := s.localTrack.Write(pk); writeErr != nil {
				tr.logger.Debug("WriteRTP failed", "subscriber", s.peerID, "error", writeErr)
			}
		}
		tr.mu.RUnlock()
	}
}

func (tr *trackRouter) Close() {
	close(tr.stopCh)
}
