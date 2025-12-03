package sfu

import "github.com/pion/webrtc/v4"

type Publisher struct {
	id string
	pc *webrtc.PeerConnection
}

func NewPublisher(id string, pc *webrtc.PeerConnection) *Publisher {
	return &Publisher{
		id: id,
		pc: pc,
	}
}

func (p *Publisher) ID() string {
	return p.id
}

func (p *Publisher) Close() {
	p.pc.Close()
}
