package sfu

type SFU struct {
	id    string
	peers map[string]Peer
}
