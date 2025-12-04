package sfu

import (
	"sync"

	"github.com/pion/webrtc/v4"
)

type Subscriber struct {
	id string
	pc *webrtc.PeerConnection
	mu sync.RWMutex

	downTracks map[string][]*webrtc.TrackRemote
}

type SubscriberOptions func(*Subscriber)

func DefaultSubscriberOptions() SubscriberOptions {
	return func(s *Subscriber) {
		s.pc, _ = webrtc.NewPeerConnection(webrtc.Configuration{})
		s.downTracks = make(map[string][]*webrtc.TrackRemote)
	}
}

func NewSubscriber(opts ...SubscriberOptions) *Subscriber {
	subscriber := &Subscriber{}
	for _, opt := range opts {
		opt(subscriber)
	}
	return subscriber
}

func (s *Subscriber) Close() error {
	s.pc.Close()
	return nil
}

func (s *Subscriber) AddDownTrack(track *webrtc.TrackRemote) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.downTracks[track.ID()] = append(s.downTracks[track.ID()], track)
	return nil
}

func (s *Subscriber) RemoveDownTrack(track *webrtc.TrackRemote) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, t := range s.downTracks[track.ID()] {
		if t == track {
			s.downTracks[track.ID()] = append(s.downTracks[track.ID()][:i], s.downTracks[track.ID()][i+1:]...)
			return nil
		}
	}
	return nil
}
