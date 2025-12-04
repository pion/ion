package sfu

import "github.com/pion/webrtc/v4"

type Publisher struct {
	pc *webrtc.PeerConnection
}

type PublisherOptions func(*Publisher)

func DefaultPublisherOptions() PublisherOptions {
	return func(p *Publisher) {
		p.pc, _ = webrtc.NewPeerConnection(webrtc.Configuration{})
	}
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
