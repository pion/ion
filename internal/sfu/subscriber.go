package sfu

import (
	"sync"
	"sync/atomic"

	"github.com/pion/ion/v2/internal/sfu/proto"
	"github.com/pion/webrtc/v4"
)

type Subscriber struct {
	pc                      *webrtc.PeerConnection
	onICECandidate          atomic.Value
	onConnectionStateChange atomic.Value
	onTrack                 atomic.Value
	onNegotiationNeeded     atomic.Value
	negotiationNeeded       atomic.Bool
	mu                      sync.RWMutex

	tracks map[string]*webrtc.TrackRemote
}

type SubscriberOptions func(*Subscriber)

func WithDefaultSubscriberOptions() SubscriberOptions {
	return func(s *Subscriber) {

		s.pc, _ = webrtc.NewPeerConnection(webrtc.Configuration{})
		s.pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{
			Direction: webrtc.RTPTransceiverDirectionRecvonly,
		})
		s.pc.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio, webrtc.RTPTransceiverInit{
			Direction: webrtc.RTPTransceiverDirectionRecvonly,
		})

		s.pc.OnICECandidate(func(c *webrtc.ICECandidate) {
			if c == nil {
				return
			}
			handler := s.onICECandidate.Load().(func(c *webrtc.ICECandidate))
			handler(c)
		})
		s.pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
			handler := s.onConnectionStateChange.Load().(func(state webrtc.PeerConnectionState))
			handler(state)
		})
		s.pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
			handler := s.onTrack.Load().(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver))
			handler(track, receiver)
		})
		s.pc.OnNegotiationNeeded(func() {
			if v := s.onNegotiationNeeded.Load(); v != nil {
				handler := v.(func())
				handler()
			}
		})
	}
}
func (s *Subscriber) SetOnICECandidateHandler(handler func(c *webrtc.ICECandidate)) {
	s.onICECandidate.Store(handler)
}

func (s *Subscriber) SetOnConnectionStateChangeHandler(handler func(state webrtc.PeerConnectionState)) {
	s.onConnectionStateChange.Store(handler)
}

func (s *Subscriber) SetOnTrackHandler(handler func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver)) {
	s.onTrack.Store(handler)
}

func (s *Subscriber) SetOnNegotiationNeededHandler(handler func()) {
	s.onNegotiationNeeded.Store(handler)
}

func (s *Subscriber) AddOutgoingTrack(track webrtc.TrackLocal) (*webrtc.RTPSender, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pc.AddTrack(track)
}

func (s *Subscriber) ClearSenders() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sender := range s.pc.GetSenders() {
		if sender.Track() != nil {
			if err := s.pc.RemoveTrack(sender); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Subscriber) InitalizeDefaultHandlers(peer Peer) {
	s.SetOnICECandidateHandler(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		resp := &proto.SignalResponse{
			SessionId:     peer.SessionID(),
			ParticipantId: peer.ParticipantID(),
			PeerId:        peer.ID(),
			Payload: &proto.SignalResponse_Candidate{
				Candidate: candidateInitToProto(c.ToJSON(), "subscriber"),
			},
		}
		peer.SignalWriteCh() <- resp
	})
	s.SetOnConnectionStateChangeHandler(func(state webrtc.PeerConnectionState) {
		peer.Logger().Info("Subscriber connection state change", "state", state)
	})
	s.SetOnTrackHandler(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		peer.Logger().Warn("Subscriber received remote track", "track_id", track.ID(), "kind", track.Kind())
	})
	s.SetOnNegotiationNeededHandler(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.pc.SignalingState() != webrtc.SignalingStateStable {
			peer.Logger().Info("Subscriber renegotiation skipped, signaling state not stable", "signaling_state", s.pc.SignalingState())
			s.negotiationNeeded.Store(true)
			return
		}
		peer.Logger().Info("Subscriber negotiation needed")
		if err := s.Renegotiate(peer); err != nil {
			peer.Logger().Error("Subscriber renegotiation failed", "error", err)
		}
	})
}

func (s *Subscriber) Renegotiate(peer Peer) error {
	peer.Logger().Debug("Renegotiate", "peer_id", peer.ID(), "session_id", peer.SessionID(), "participant_id", peer.ParticipantID())

	offer, err := s.pc.CreateOffer(nil)
	if err != nil {
		return err
	}
	if err := s.pc.SetLocalDescription(offer); err != nil {
		return err
	}

	resp := &proto.SignalResponse{
		SessionId:     peer.SessionID(),
		ParticipantId: peer.ParticipantID(),
		PeerId:        peer.ID(),
		Payload: &proto.SignalResponse_Sdp{
			Sdp: &proto.SessionDescription{
				Role: "subscriber",
				Type: "offer",
				Sdp:  offer.SDP,
			},
		},
	}

	peer.SignalWriteCh() <- resp
	return nil
}

func NewSubscriber(opts ...SubscriberOptions) *Subscriber {
	subscriber := &Subscriber{
		tracks: make(map[string]*webrtc.TrackRemote),
	}
	for _, opt := range opts {
		opt(subscriber)
	}
	return subscriber
}

func (s *Subscriber) Close() error {
	s.pc.Close()
	return nil
}
