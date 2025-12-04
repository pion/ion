package sfu

import (
	"context"
	"io"
	"log"
	"sync"

	"github.com/pion/ion/v2/internal/logger"
	"github.com/pion/ion/v2/internal/sfu/proto"
	"github.com/pion/webrtc/v4"
)

const scope = "sfu-server"

// SFUServer implements the signaling service for SFU
type SFUServer struct {
	proto.UnimplementedSFUServiceServer
	lf *logger.LoggerFactory

	SFU *SFU
	sync.Mutex
}

func NewSFUServer(lf *logger.LoggerFactory) *SFUServer {
	return &SFUServer{
		SFU: &SFU{
			peers: make(map[string]Peer),
		},
		lf: lf,
	}
}

func (s *SFUServer) HealthCheck(ctx context.Context, req *proto.HealthCheckRequest) (*proto.HealthCheckResponse, error) {
	logger := s.lf.ForScope(scope)
	logger.Info("HealthCheck", "worker_id", s.SFU.id)
	return &proto.HealthCheckResponse{
		WorkerId: s.SFU.id,
		Ok:       true,
	}, nil
}

func (s *SFUServer) Signal(stream proto.SFUService_SignalServer) error {
	ctx := stream.Context()
	logger := s.lf.ForScope(scope)
	logger.Info("Start handling signal")
	sendCh := make(chan *proto.SignalResponse, 64)
	senderErrCh := make(chan error, 1)
	go func() {
		defer close(senderErrCh)
		for {
			select {
			case <-ctx.Done():
				logger.Debug("sender exiting due to context done")
				return
			case msg, ok := <-sendCh:
				if !ok {
					logger.Debug("sender exiting, sendCh closed")
					return
				}
				if err := stream.Send(msg); err != nil {
					logger.Error("Error sending signal", "error", err)
					senderErrCh <- err
					return
				}
			}
		}
	}()
	for {
		req, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				logger.Info("EOF")
				return nil
			}
			logger.Error("Error receiving signal", "error", err)
			return err
		}

		switch req.Payload.(type) {
		case *proto.SignalRequest_Join:
			logger.Debug("Join", "session_id", req.SessionId, "participant_id", req.ParticipantId)
			peer := NewLocalPeer(s.lf, req.SessionId, req.ParticipantId, sendCh, DefaultPeerLocalOptions())
			s.SFU.addPeer(peer)
			sendCh <- &proto.SignalResponse{
				SessionId:     req.SessionId,
				ParticipantId: req.ParticipantId,
				PeerId:        peer.ID(),
			}

			// peer.Publisher().pc.OnICECandidate(func(c *webrtc.ICECandidate) {
			// 	if c == nil {
			// 		return
			// 	}
			// 	resp := &proto.SignalResponse{
			// 		RoomId:        peer.sessionID,
			// 		ParticipantId: peer.participantID,
			// 		Payload: &proto.SignalResponse_Candidate{
			// 			Candidate: candidateInitToProto(c.ToJSON(), "publisher"),
			// 		},
			// 	}
			// 	stream.Send(resp)
			// })
			// peer.Publisher().pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
			// 	log.Println(state)
			// })
			// peer.publisher.pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
			// 	localTrack, err := webrtc.NewTrackLocalStaticRTP(
			// 		track.Codec().RTPCodecCapability,
			// 		track.ID(),       // reuse ID for simplicity
			// 		track.StreamID(), // reuse stream ID
			// 	)
			// 	if err != nil {
			// 		log.Printf("NewTrackLocalStaticRTP: %v", err)
			// 		return
			// 	}
			// 	sender, err := peer.subscriber.pc.AddTrack(localTrack)
			// 	if err != nil {
			// 		log.Printf("subPC.AddTrack error: %v", err)
			// 		return
			// 	}
			// 	go func() {
			// 		buf := make([]byte, 1500)
			// 		for {
			// 			if _, _, err := sender.Read(buf); err != nil {
			// 				log.Printf("subscriber sender RTCP read error: %v", err)
			// 				return
			// 			}
			// 		}
			// 	}()
			// 	go func() {
			// 		buf := make([]byte, 1500)
			// 		for {
			// 			n, _, err := track.Read(buf)
			// 			if err != nil {
			// 				log.Printf("remote track read error: %v", err)
			// 				return
			// 			}

			// 			if _, writeErr := localTrack.Write(buf[:n]); writeErr != nil {
			// 				log.Printf("localTrack.Write error: %v", writeErr)
			// 				return
			// 			}
			// 		}
			// 	}()
			// 	go func() {
			// 		for peer.subscriber.pc.SignalingState() != webrtc.SignalingStateStable {
			// 			time.Sleep(100 * time.Millisecond)
			// 			log.Printf("subPC renegotiation skipped; signaling state = %s", peer.subscriber.pc.SignalingState())
			// 		}
			// 		offer, err := peer.subscriber.pc.CreateOffer(nil)
			// 		if err != nil {
			// 			log.Printf("subPC.CreateOffer error: %v", err)
			// 			return
			// 		}
			// 		if err := peer.subscriber.pc.SetLocalDescription(offer); err != nil {
			// 			log.Printf("subPC.SetLocalDescription error: %v", err)
			// 			return
			// 		}

			// 		// Send this offer to the client (subscriber PC).
			// 		// You’ll need a way to distinguish “subscriber” vs “publisher” SDP in your proto.
			// 		resp := &proto.SignalResponse{
			// 			RoomId:        peer.sessionID,
			// 			ParticipantId: peer.participantID,
			// 			Payload: &proto.SignalResponse_Sdp{
			// 				Sdp: &proto.SessionDescription{
			// 					Role: "subscriber",
			// 					Type: "offer",
			// 					Sdp:  offer.SDP,
			// 				},
			// 			},
			// 		}
			// 		err = stream.Send(resp)
			// 		if err != nil {
			// 			log.Printf("stream.Send error: %v", err)
			// 			return
			// 		}
			// 	}()
			// })
			// s.SFU.peers[peer.ID()] = peer
		case *proto.SignalRequest_Leave:
			peer, err := s.SFU.getPeer(req.PeerId)
			if err != nil {
				logger.Error("Leave", "peer_id", req.PeerId, "session_id", req.SessionId, "participant_id", req.ParticipantId, "error", err)
			}
			peer.Close()
			logger.Info("Leave", "peer_id", req.PeerId, "session_id", req.SessionId, "participant_id", req.ParticipantId)
		case *proto.SignalRequest_Sdp:
			peer, err := s.SFU.getPeer(req.PeerId)
			if err != nil {
				logger.Error("SDP", "peer_id", req.PeerId, "session_id", req.SessionId, "participant_id", req.ParticipantId, "error", err)
			}

			logger.Info("SDP", "peer_id", req.PeerId, "session_id", req.SessionId, "participant_id", req.ParticipantId, "type", req.GetSdp().Type)
			logger.Debug("SDP", "sdp", req.GetSdp().Sdp)

			sdp := req.GetSdp()

			switch sdp.Type {
			case "offer":
				resp, err := handleSDPOffer(peer, sdp)
				if err != nil {
					logger.Error("handleSDPOffer", "error", err)
				}
				sendCh <- resp
			case "answer":
				err := peer.Subscriber().pc.SetRemoteDescription(webrtc.SessionDescription{
					Type: webrtc.SDPTypeAnswer,
					SDP:  sdp.Sdp,
				})
				if err != nil {
					logger.Error("subPC.SetRemoteDescription(answer)", "error", err)
				}
			}
		case *proto.SignalRequest_Candidate:
			logger.Info("Candidate", "peer_id", req.PeerId, "session_id", req.SessionId, "participant_id", req.ParticipantId)
			cand := req.GetCandidate()
			if cand == nil {
				continue
			}
			peer, err := s.SFU.getPeer(req.PeerId)
			if err != nil {
				logger.Error("Candidate", "peer_id", req.PeerId, "session_id", req.SessionId, "participant_id", req.ParticipantId, "error", err)
			}

			switch cand.Role {
			case "publisher":
				if err := peer.Publisher().pc.AddICECandidate(candidateProtoToInit(cand)); err != nil {
					logger.Error("AddICECandidate", "error", err)
				}
			case "subscriber":
				if err := peer.Subscriber().pc.AddICECandidate(candidateProtoToInit(cand)); err != nil {
					logger.Error("AddICECandidate", "error", err)
				}
			}
		default:
			logger.Error("Unknown signal type", "signal", req)
		}
	}
}

func candidateProtoToInit(c *proto.IceCandidate) webrtc.ICECandidateInit {
	return webrtc.ICECandidateInit{
		Candidate:        c.Candidate,
		SDPMid:           &c.SdpMid,
		SDPMLineIndex:    func() *uint16 { v := uint16(c.SdpMlineIndex); return &v }(),
		UsernameFragment: &c.UsernameFragment,
	}
}

func candidateInitToProto(c webrtc.ICECandidateInit, t string) *proto.IceCandidate {
	var mid string
	var mline int32
	var ufrag string

	if c.SDPMid != nil {
		mid = *c.SDPMid
	}
	if c.SDPMLineIndex != nil {
		mline = int32(*c.SDPMLineIndex)
	}
	if c.UsernameFragment != nil {
		ufrag = *c.UsernameFragment
	}

	return &proto.IceCandidate{
		Role:             t,
		Candidate:        c.Candidate,
		SdpMid:           mid,
		SdpMlineIndex:    mline,
		UsernameFragment: ufrag,
	}
}

func handleSDPOffer(peer Peer, sdp *proto.SessionDescription) (*proto.SignalResponse, error) {
	peer.Publisher().pc.SetRemoteDescription(
		webrtc.SessionDescription{
			Type: webrtc.SDPTypeOffer,
			SDP:  sdp.Sdp,
		},
	)
	answer, err := peer.Publisher().pc.CreateAnswer(nil)
	if err != nil {
		log.Printf("CreateAnswer: %v", err)
		return nil, err
	}
	if err := peer.Publisher().pc.SetLocalDescription(answer); err != nil {
		log.Printf("SetLocalDescription: %v", err)
		return nil, err
	}
	resp := &proto.SignalResponse{
		SessionId:     peer.SessionID(),
		ParticipantId: peer.ParticipantID(),
		Payload: &proto.SignalResponse_Sdp{
			Sdp: &proto.SessionDescription{
				Role: "publisher",
				Type: "answer",
				Sdp:  answer.SDP,
			},
		},
	}

	return resp, nil
}
