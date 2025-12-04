package sfu

import (
	"sync"

	"github.com/google/uuid"
)

type Peer interface {
	ID() string
	ParticipantID() string
	SessionID() string

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

type PeerLocalOptions func(*PeerLocal)

func DefaultPeerLocalOptions() PeerLocalOptions {
	return func(p *PeerLocal) {
		p.publisher = NewPublisher(DefaultPublisherOptions())
		p.subscriber = NewSubscriber(DefaultSubscriberOptions())
		p.remoteAnswerPending = false
		p.negotiationPending = false
	}
}

func NewLocalPeer(sessionID string, participantID string, opts ...PeerLocalOptions) *PeerLocal {
	peer := &PeerLocal{
		id:            uuid.New().String(),
		sessionID:     sessionID,
		participantID: participantID,
		closed:        false,
	}
	for _, opt := range opts {
		opt(peer)
	}
	return peer
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

func (p *PeerLocal) SessionID() string {
	return p.sessionID
}
