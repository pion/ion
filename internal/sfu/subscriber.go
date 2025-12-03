package sfu

import "github.com/pion/webrtc/v4"

type Subscriber struct {
	id string
	pc *webrtc.PeerConnection

	downTracks map[string][]*webrtc.TrackRemote
}

func NewSubscriber(id string, pc *webrtc.PeerConnection) *Subscriber {
	return &Subscriber{
		id:         id,
		pc:         pc,
		downTracks: make(map[string][]*webrtc.TrackRemote),
	}
}

func (s *Subscriber) ID() string {
	return s.id
}

func (s *Subscriber) Close() error {
	s.pc.Close()
	return nil
}

func (s *Subscriber) AddDownTrack(track *webrtc.TrackRemote) error {
	s.downTracks[track.ID()] = append(s.downTracks[track.ID()], track)
	return nil
}

func (s *Subscriber) RemoveDownTrack(track *webrtc.TrackRemote) error {
	for i, t := range s.downTracks[track.ID()] {
		if t == track {
			s.downTracks[track.ID()] = append(s.downTracks[track.ID()][:i], s.downTracks[track.ID()][i+1:]...)
			return nil
		}
	}
	return nil
}
