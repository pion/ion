package sfu

import (
	"log/slog"
	"sync"

	"github.com/google/uuid"
	"github.com/pion/ion/v2/internal/logger"
	"github.com/pion/ion/v2/internal/sfu/proto"
)

type Peer interface {
	ID() string
	ParticipantID() string
	SessionID() string

	Publisher() *Publisher
	Subscriber() *Subscriber
	SignalWriteCh() chan *proto.SignalResponse
	Logger() *slog.Logger

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
	signalWriteCh       chan *proto.SignalResponse
	logger              *slog.Logger

	publisher  *Publisher
	subscriber *Subscriber
}

type PeerLocalOptions func(*PeerLocal)

func DefaultPeerLocalOptions() PeerLocalOptions {
	return func(p *PeerLocal) {
		p.publisher = NewPublisher(WithDefaultPublisherOptions())
		p.publisher.InitalizeDefaultHandlers(p)
		p.subscriber = NewSubscriber(WithDefaultSubscriberOptions())
		p.subscriber.InitalizeDefaultHandlers(p)
		p.remoteAnswerPending = false
		p.negotiationPending = false
	}
}

func NewLocalPeer(lf *logger.LoggerFactory, sessionID string, participantID string, sigWriteCh chan *proto.SignalResponse, opts ...PeerLocalOptions) *PeerLocal {
	peerID := uuid.New().String()

	logger := lf.ForScope("peer").With(
		"session_id", sessionID,
		"participant_id", participantID,
		"peer_id", peerID,
	)
	logger.Info("NewLocalPeer created")

	peer := &PeerLocal{
		id:            peerID,
		sessionID:     sessionID,
		participantID: participantID,
		closed:        false,
		signalWriteCh: sigWriteCh,
		logger:        logger,
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

func (p *PeerLocal) SignalWriteCh() chan *proto.SignalResponse {
	return p.signalWriteCh
}

func (p *PeerLocal) Logger() *slog.Logger {
	return p.logger
}
