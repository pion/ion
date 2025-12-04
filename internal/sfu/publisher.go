package sfu

import (
	"sync/atomic"

	"github.com/pion/ion/v2/internal/sfu/proto"
	"github.com/pion/webrtc/v4"
)

type Publisher struct {
	pc                      *webrtc.PeerConnection
	onICECandidate          atomic.Value
	onConnectionStateChange atomic.Value
	onTrack                 atomic.Value
}

type PublisherOptions func(*Publisher)

func WithDefaultPublisherOptions() PublisherOptions {
	return func(p *Publisher) {

		p.pc, _ = webrtc.NewPeerConnection(webrtc.Configuration{})

		p.pc.OnICECandidate(func(c *webrtc.ICECandidate) {
			if c == nil {
				return
			}
			handler := p.onICECandidate.Load().(func(c *webrtc.ICECandidate))
			handler(c)
		})
		p.pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
			handler := p.onConnectionStateChange.Load().(func(state webrtc.PeerConnectionState))
			handler(state)
		})
		p.pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
			handler := p.onTrack.Load().(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver))
			handler(track, receiver)
		})
	}
}

func (p *Publisher) SetOnICECandidateHandler(handler func(c *webrtc.ICECandidate)) {
	p.onICECandidate.Store(handler)
}

func (p *Publisher) SetOnConnectionStateChangeHandler(handler func(state webrtc.PeerConnectionState)) {
	p.onConnectionStateChange.Store(handler)
}

func (p *Publisher) SetOnTrackHandler(handler func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver)) {
	p.onTrack.Store(handler)
}

func (p *Publisher) InitalizeDefaultHandlers(peer Peer) {
	p.SetOnICECandidateHandler(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		resp := &proto.SignalResponse{
			SessionId:     peer.SessionID(),
			ParticipantId: peer.ParticipantID(),
			PeerId:        peer.ID(),
			Payload: &proto.SignalResponse_Candidate{
				Candidate: candidateInitToProto(c.ToJSON(), "publisher"),
			},
		}
		peer.SignalWriteCh() <- resp
	})
	p.SetOnConnectionStateChangeHandler(func(state webrtc.PeerConnectionState) {
		peer.Logger().Info("Publisher connection state change", "state", state)
	})
	p.SetOnTrackHandler(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		peer.Logger().Info("Publisher track added", "track_id", track.ID())
	})
}

func NewPublisher(opts ...PublisherOptions) *Publisher {
	publisher := &Publisher{}
	for _, opt := range opts {
		opt(publisher)
	}
	return publisher
}

func (p *Publisher) Close() {
	p.pc.Close()
}
