package sfu

import (
	"sync"

	"github.com/google/uuid"
	"github.com/pion/webrtc/v4"
)

type Peer interface {
	ID() string
	ParticipantID() string

	Publisher() *Publisher
	Subscriber() *Subscriber

	Close()
}

type PeerLocal struct {
	sync.Mutex
	id            string
	closed        bool
	sessionID     string
	participantID string

	remoteAnswerPending bool
	negotiationPending  bool

	publisher  *Publisher
	subscriber *Subscriber
}

func NewLocalPeer(sessionID string, participantID string) *PeerLocal {
	pcPub, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return nil
	}
	pcSub, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return nil
	}
	id := uuid.New().String()
	return &PeerLocal{
		id:                  id,
		sessionID:           sessionID,
		participantID:       participantID,
		remoteAnswerPending: false,
		negotiationPending:  false,
		publisher:           NewPublisher(id, pcPub),
		subscriber:          NewSubscriber(id, pcSub),
	}
}

func (p *PeerLocal) ID() string {
	return p.id
}

func (p *PeerLocal) ParticipantID() string {
	return p.participantID
}

func (p *PeerLocal) Close() {
	p.Mutex.Lock()
	defer p.Mutex.Unlock()
	p.closed = true
	p.publisher.Close()
	p.subscriber.Close()
}

func (p *PeerLocal) Publisher() *Publisher {
	return p.publisher
}

func (p *PeerLocal) Subscriber() *Subscriber {
	return p.subscriber
}
