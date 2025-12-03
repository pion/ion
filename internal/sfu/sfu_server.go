package sfu

import (
	"context"
	"io"
	"log"
	"sync"
	"time"

	"github.com/pion/ion/v2/internal/sfu/proto"
	"github.com/pion/webrtc/v4"
)

// SFUServer implements the signaling service for SFU
type SFUServer struct {
	proto.UnimplementedSFUServiceServer

	SFU *SFU
	sync.Mutex
}

func NewSFUServer() *SFUServer {
	return &SFUServer{
		SFU: &SFU{
			peers: make(map[string]Peer),
		},
	}
}

func (s *SFUServer) HealthCheck(ctx context.Context, req *proto.HealthCheckRequest) (*proto.HealthCheckResponse, error) {
	return &proto.HealthCheckResponse{
		WorkerId: s.SFU.id,
		Ok:       true,
	}, nil
}

func (s *SFUServer) Signal(stream proto.SFUService_SignalServer) error {
	var peer *PeerLocal
	for {
		req, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				log.Print("EOF")
				return nil
			}
			return err
		}
		switch req.Payload.(type) {
		case *proto.SignalRequest_Join:
			log.Printf("Join: %v", req)
			reqJoin := req.GetJoin()
			peer = NewLocalPeer(reqJoin.SessionId, reqJoin.ParticipantId)
			peer.Publisher().pc.OnICECandidate(func(c *webrtc.ICECandidate) {
				if c == nil {
					return
				}
				resp := &proto.SignalResponse{
					RoomId:        peer.sessionID,
					ParticipantId: peer.participantID,
					Payload: &proto.SignalResponse_Candidate{
						Candidate: candidateInitToProto(c.ToJSON(), "publisher"),
					},
				}
				stream.Send(resp)
			})
			peer.Publisher().pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
				log.Println(state)
			})
			peer.publisher.pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
				localTrack, err := webrtc.NewTrackLocalStaticRTP(
					track.Codec().RTPCodecCapability,
					track.ID(),       // reuse ID for simplicity
					track.StreamID(), // reuse stream ID
				)
				if err != nil {
					log.Printf("NewTrackLocalStaticRTP: %v", err)
					return
				}
				sender, err := peer.subscriber.pc.AddTrack(localTrack)
				if err != nil {
					log.Printf("subPC.AddTrack error: %v", err)
					return
				}
				go func() {
					buf := make([]byte, 1500)
					for {
						if _, _, err := sender.Read(buf); err != nil {
							log.Printf("subscriber sender RTCP read error: %v", err)
							return
						}
					}
				}()
				go func() {
					buf := make([]byte, 1500)
					for {
						n, _, err := track.Read(buf)
						if err != nil {
							log.Printf("remote track read error: %v", err)
							return
						}

						if _, writeErr := localTrack.Write(buf[:n]); writeErr != nil {
							log.Printf("localTrack.Write error: %v", writeErr)
							return
						}
					}
				}()
				go func() {
					for peer.subscriber.pc.SignalingState() != webrtc.SignalingStateStable {
						time.Sleep(100 * time.Millisecond)
						log.Printf("subPC renegotiation skipped; signaling state = %s", peer.subscriber.pc.SignalingState())
					}
					offer, err := peer.subscriber.pc.CreateOffer(nil)
					if err != nil {
						log.Printf("subPC.CreateOffer error: %v", err)
						return
					}
					if err := peer.subscriber.pc.SetLocalDescription(offer); err != nil {
						log.Printf("subPC.SetLocalDescription error: %v", err)
						return
					}

					// Send this offer to the client (subscriber PC).
					// You’ll need a way to distinguish “subscriber” vs “publisher” SDP in your proto.
					resp := &proto.SignalResponse{
						RoomId:        peer.sessionID,
						ParticipantId: peer.participantID,
						Payload: &proto.SignalResponse_Sdp{
							Sdp: &proto.SessionDescription{
								Role: "subscriber",
								Type: "offer",
								Sdp:  offer.SDP,
							},
						},
					}
					err = stream.Send(resp)
					if err != nil {
						log.Printf("stream.Send error: %v", err)
						return
					}
				}()
			})
			s.SFU.peers[peer.ID()] = peer
		case *proto.SignalRequest_Leave:
			peer.Close()
			log.Printf("Leave: %v", req)
		case *proto.SignalRequest_Sdp:
			log.Printf("SDP: %v", req)
			sdp := req.GetSdp()
			if peer == nil {
				log.Printf("Unknown peer: %v", req)
				return nil
			}
			if sdp.Type == "offer" {
				log.Println(peer.Publisher())
				peer.Publisher().pc.SetRemoteDescription(
					webrtc.SessionDescription{
						Type: webrtc.SDPTypeOffer,
						SDP:  sdp.Sdp,
					},
				)
				answer, err := peer.Publisher().pc.CreateAnswer(nil)
				if err != nil {
					log.Printf("CreateAnswer: %v", err)
					return err
				}
				if err := peer.Publisher().pc.SetLocalDescription(answer); err != nil {
					log.Printf("SetLocalDescription: %v", err)
					return err
				}
				resp := &proto.SignalResponse{
					RoomId:        peer.sessionID,
					ParticipantId: peer.participantID,
					Payload: &proto.SignalResponse_Sdp{
						Sdp: &proto.SessionDescription{
							Role: "publisher",
							Type: "answer",
							Sdp:  answer.SDP,
						},
					},
				}
				stream.Send(resp)
			}
			if sdp.Type == "answer" {
				log.Println("answer")
				err := peer.Subscriber().pc.SetRemoteDescription(webrtc.SessionDescription{
					Type: webrtc.SDPTypeAnswer,
					SDP:  sdp.Sdp,
				})
				if err != nil {
					log.Printf("subPC.SetRemoteDescription(answer) error: %v", err)
				}
			}
		case *proto.SignalRequest_Candidate:
			log.Printf("Candidate: %v", req)
			cand := req.GetCandidate()
			if cand == nil {
				continue
			}
			if cand.Role == "publisher" {
				if err := peer.Publisher().pc.AddICECandidate(candidateProtoToInit(cand)); err != nil {
					log.Printf("AddICECandidate: %v", err)
				}
			}
			if cand.Role == "subscriber" {
				if err := peer.Subscriber().pc.AddICECandidate(candidateProtoToInit(cand)); err != nil {
					log.Printf("AddICECandidate: %v", err)
				}
			}

		default:
			log.Printf("Unknown signal type: %v", req)
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
