package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/pion/ion/v2/internal/sfu/proto"
	"github.com/rs/cors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true }, // tighten later
}

type signalMessage struct {
	Type      string          `json:"type"`           // "offer", "answer", "candidate"
	Role      string          `json:"role,omitempty"` // "publisher" or "subscriber"
	SDP       string          `json:"sdp,omitempty"`
	Candidate json.RawMessage `json:"candidate,omitempty"`
}

type iceCandidateJSON struct {
	Candidate        string  `json:"candidate"`
	SdpMid           *string `json:"sdpMid"`
	SdpMLineIndex    *uint16 `json:"sdpMLineIndex"`
	UsernameFragment *string `json:"usernameFragment"`
}

func main() {

	// For now: single worker at localhost:50051
	workerAddr := "localhost:50051"
	conn, err := grpc.Dial(workerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("failed to dial worker: %v", err)
	}
	defer conn.Close()
	workerClient := proto.NewSFUServiceClient(conn)

	mux := http.NewServeMux()

	// WS signaling (router)
	mux.HandleFunc("/signal", SignalHandler(workerClient))

	// static frontend
	fs := http.FileServer(http.Dir("./cmd/control/web"))
	mux.Handle("/", fs)

	handler := cors.AllowAll().Handler(mux)
	addr := ":8080"
	if env := os.Getenv("CONTROL_HTTP_ADDR"); env != "" {
		addr = env
	}

	log.Printf("Control listening on %s", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("http server error: %v", err)
	}
}

func candidateJSONToProto(j iceCandidateJSON, role string) *proto.IceCandidate {
	var mid string
	var mline int32
	var ufrag string
	if j.SdpMid != nil {
		mid = *j.SdpMid
	}
	if j.SdpMLineIndex != nil {
		mline = int32(*j.SdpMLineIndex)
	}
	if j.UsernameFragment != nil {
		ufrag = *j.UsernameFragment
	}
	return &proto.IceCandidate{
		Role:             role,
		Candidate:        j.Candidate,
		SdpMid:           mid,
		SdpMlineIndex:    mline,
		UsernameFragment: ufrag,
	}
}

func candidateProtoToJSON(c *proto.IceCandidate) iceCandidateJSON {
	var mid *string
	var mline *uint16
	var ufrag *string

	if c.SdpMid != "" {
		m := c.SdpMid
		mid = &m
	}
	if c.SdpMlineIndex != 0 {
		v := uint16(c.SdpMlineIndex)
		mline = &v
	}
	if c.UsernameFragment != "" {
		u := c.UsernameFragment
		ufrag = &u
	}

	return iceCandidateJSON{
		Candidate:        c.Candidate,
		SdpMid:           mid,
		SdpMLineIndex:    mline,
		UsernameFragment: ufrag,
	}
}

func SignalHandler(workerClient proto.SFUServiceClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Assume only single room right now
		roomID := "room-1"

		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("ws upgrade error: %v", err)
			return
		}
		defer ws.Close()

		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		participantID := uuid.NewString()
		log.Printf("WS signaling connected room=%s participant=%s", roomID, participantID)

		stream, err := workerClient.Signal(ctx)
		if err != nil {
			log.Printf("Signal RPC error: %v", err)
			return
		}

		// First message: Join
		if err := stream.Send(&proto.SignalRequest{
			RoomId:        roomID,
			ParticipantId: participantID,
			Payload:       &proto.SignalRequest_Join{Join: &proto.Join{}},
		}); err != nil {
			log.Printf("Send Join error: %v", err)
			return
		}

		var sendMu sync.Mutex
		sendWS := func(v any) error {
			sendMu.Lock()
			defer sendMu.Unlock()
			return ws.WriteJSON(v)
		}

		// Goroutine: read from WS -> send to worker
		wsErrCh := make(chan error, 1)
		go func() {
			defer close(wsErrCh)
			for {
				var msg signalMessage
				if err := ws.ReadJSON(&msg); err != nil {
					wsErrCh <- err
					return
				}

				switch msg.Type {
				case "offer", "answer":
					req := &proto.SignalRequest{
						RoomId:        roomID,
						ParticipantId: participantID,
						Payload: &proto.SignalRequest_Sdp{
							Sdp: &proto.SessionDescription{
								Role: msg.Role,
								Type: msg.Type,
								Sdp:  msg.SDP,
							},
						},
					}
					if err := stream.Send(req); err != nil {
						wsErrCh <- err
						return
					}

				case "candidate":
					if len(msg.Candidate) == 0 {
						continue
					}
					var cj iceCandidateJSON
					if err := json.Unmarshal(msg.Candidate, &cj); err != nil {
						log.Printf("candidate json unmarshal error: %v", err)
						continue
					}
					req := &proto.SignalRequest{
						RoomId:        roomID,
						ParticipantId: participantID,
						Payload: &proto.SignalRequest_Candidate{
							Candidate: candidateJSONToProto(cj, msg.Role),
						},
					}
					if err := stream.Send(req); err != nil {
						wsErrCh <- err
						return
					}
				default:
					log.Printf("Unknown WS msg type: %s", msg.Type)
				}
			}
		}()

		// Goroutine: read from worker -> send to WS
		grpcErrCh := make(chan error, 1)
		go func() {
			defer close(grpcErrCh)
			for {
				resp, err := stream.Recv()
				if err != nil {
					grpcErrCh <- err
					return
				}
				switch payload := resp.Payload.(type) {
				case *proto.SignalResponse_Sdp:

					out := signalMessage{
						Type: payload.Sdp.Type,
						Role: payload.Sdp.Role,
						SDP:  payload.Sdp.Sdp,
					}
					if err := sendWS(out); err != nil {
						grpcErrCh <- err
						return
					}

				case *proto.SignalResponse_Candidate:
					cj := candidateProtoToJSON(payload.Candidate)
					raw, _ := json.Marshal(cj)
					out := signalMessage{
						Type:      "candidate",
						Role:      payload.Candidate.Role,
						Candidate: raw,
					}
					if err := sendWS(out); err != nil {
						grpcErrCh <- err
						return
					}
				default:
					log.Printf("Unknown SignalResponse payload")
				}
			}
		}()

		// Wait for either side to close
		select {
		case err := <-wsErrCh:
			log.Printf("WS closed room=%s participant=%s: %v", roomID, participantID, err)
			_ = stream.Send(&proto.SignalRequest{
				RoomId:        roomID,
				ParticipantId: participantID,
				Payload:       &proto.SignalRequest_Leave{Leave: &proto.Leave{}},
			})
		case err := <-grpcErrCh:
			log.Printf("gRPC stream closed room=%s participant=%s: %v", roomID, participantID, err)
		case <-ctx.Done():
			log.Printf("ctx done room=%s participant=%s", roomID, participantID)
		}
	}
}
