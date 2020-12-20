// Code generated by protoc-gen-go. DO NOT EDIT.
// source: cmd/biz/grpc/proto/biz.proto

package proto

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type Trickle_Target int32

const (
	Trickle_PUBLISHER  Trickle_Target = 0
	Trickle_SUBSCRIBER Trickle_Target = 1
)

var Trickle_Target_name = map[int32]string{
	0: "PUBLISHER",
	1: "SUBSCRIBER",
}

var Trickle_Target_value = map[string]int32{
	"PUBLISHER":  0,
	"SUBSCRIBER": 1,
}

func (x Trickle_Target) String() string {
	return proto.EnumName(Trickle_Target_name, int32(x))
}

func (Trickle_Target) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_3def3f03f57c29b9, []int{7, 0}
}

type Client struct {
	Sid string `protobuf:"bytes,1,opt,name=sid,proto3" json:"sid,omitempty"`
	// Types that are valid to be assigned to Payload:
	//	*Client_Join
	//	*Client_Leave
	//	*Client_Offer
	//	*Client_Answer
	//	*Client_Trickle
	//	*Client_Broadcast
	Payload              isClient_Payload `protobuf_oneof:"payload"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *Client) Reset()         { *m = Client{} }
func (m *Client) String() string { return proto.CompactTextString(m) }
func (*Client) ProtoMessage()    {}
func (*Client) Descriptor() ([]byte, []int) {
	return fileDescriptor_3def3f03f57c29b9, []int{0}
}

func (m *Client) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Client.Unmarshal(m, b)
}
func (m *Client) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Client.Marshal(b, m, deterministic)
}
func (m *Client) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Client.Merge(m, src)
}
func (m *Client) XXX_Size() int {
	return xxx_messageInfo_Client.Size(m)
}
func (m *Client) XXX_DiscardUnknown() {
	xxx_messageInfo_Client.DiscardUnknown(m)
}

var xxx_messageInfo_Client proto.InternalMessageInfo

func (m *Client) GetSid() string {
	if m != nil {
		return m.Sid
	}
	return ""
}

type isClient_Payload interface {
	isClient_Payload()
}

type Client_Join struct {
	Join *JoinRequest `protobuf:"bytes,2,opt,name=join,proto3,oneof"`
}

type Client_Leave struct {
	Leave *LeaveRequest `protobuf:"bytes,3,opt,name=leave,proto3,oneof"`
}

type Client_Offer struct {
	Offer *Offer `protobuf:"bytes,4,opt,name=offer,proto3,oneof"`
}

type Client_Answer struct {
	Answer *Answer `protobuf:"bytes,5,opt,name=answer,proto3,oneof"`
}

type Client_Trickle struct {
	Trickle *Trickle `protobuf:"bytes,6,opt,name=trickle,proto3,oneof"`
}

type Client_Broadcast struct {
	Broadcast *Broadcast `protobuf:"bytes,7,opt,name=broadcast,proto3,oneof"`
}

func (*Client_Join) isClient_Payload() {}

func (*Client_Leave) isClient_Payload() {}

func (*Client_Offer) isClient_Payload() {}

func (*Client_Answer) isClient_Payload() {}

func (*Client_Trickle) isClient_Payload() {}

func (*Client_Broadcast) isClient_Payload() {}

func (m *Client) GetPayload() isClient_Payload {
	if m != nil {
		return m.Payload
	}
	return nil
}

func (m *Client) GetJoin() *JoinRequest {
	if x, ok := m.GetPayload().(*Client_Join); ok {
		return x.Join
	}
	return nil
}

func (m *Client) GetLeave() *LeaveRequest {
	if x, ok := m.GetPayload().(*Client_Leave); ok {
		return x.Leave
	}
	return nil
}

func (m *Client) GetOffer() *Offer {
	if x, ok := m.GetPayload().(*Client_Offer); ok {
		return x.Offer
	}
	return nil
}

func (m *Client) GetAnswer() *Answer {
	if x, ok := m.GetPayload().(*Client_Answer); ok {
		return x.Answer
	}
	return nil
}

func (m *Client) GetTrickle() *Trickle {
	if x, ok := m.GetPayload().(*Client_Trickle); ok {
		return x.Trickle
	}
	return nil
}

func (m *Client) GetBroadcast() *Broadcast {
	if x, ok := m.GetPayload().(*Client_Broadcast); ok {
		return x.Broadcast
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*Client) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*Client_Join)(nil),
		(*Client_Leave)(nil),
		(*Client_Offer)(nil),
		(*Client_Answer)(nil),
		(*Client_Trickle)(nil),
		(*Client_Broadcast)(nil),
	}
}

type Server struct {
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// Types that are valid to be assigned to Payload:
	//	*Server_Join
	//	*Server_Offer
	//	*Server_Answer
	//	*Server_TrickleEvent
	//	*Server_PeersEvent
	//	*Server_JoinEvent
	//	*Server_BroadcastEvent
	Payload              isServer_Payload `protobuf_oneof:"payload"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *Server) Reset()         { *m = Server{} }
func (m *Server) String() string { return proto.CompactTextString(m) }
func (*Server) ProtoMessage()    {}
func (*Server) Descriptor() ([]byte, []int) {
	return fileDescriptor_3def3f03f57c29b9, []int{1}
}

func (m *Server) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Server.Unmarshal(m, b)
}
func (m *Server) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Server.Marshal(b, m, deterministic)
}
func (m *Server) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Server.Merge(m, src)
}
func (m *Server) XXX_Size() int {
	return xxx_messageInfo_Server.Size(m)
}
func (m *Server) XXX_DiscardUnknown() {
	xxx_messageInfo_Server.DiscardUnknown(m)
}

var xxx_messageInfo_Server proto.InternalMessageInfo

func (m *Server) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

type isServer_Payload interface {
	isServer_Payload()
}

type Server_Join struct {
	Join *JoinReply `protobuf:"bytes,2,opt,name=join,proto3,oneof"`
}

type Server_Offer struct {
	Offer *Offer `protobuf:"bytes,3,opt,name=offer,proto3,oneof"`
}

type Server_Answer struct {
	Answer *Answer `protobuf:"bytes,4,opt,name=answer,proto3,oneof"`
}

type Server_TrickleEvent struct {
	TrickleEvent *Trickle `protobuf:"bytes,5,opt,name=trickleEvent,proto3,oneof"`
}

type Server_PeersEvent struct {
	PeersEvent *PeersEvent `protobuf:"bytes,6,opt,name=peersEvent,proto3,oneof"`
}

type Server_JoinEvent struct {
	JoinEvent *JoinEvent `protobuf:"bytes,7,opt,name=joinEvent,proto3,oneof"`
}

type Server_BroadcastEvent struct {
	BroadcastEvent *Broadcast `protobuf:"bytes,8,opt,name=broadcastEvent,proto3,oneof"`
}

func (*Server_Join) isServer_Payload() {}

func (*Server_Offer) isServer_Payload() {}

func (*Server_Answer) isServer_Payload() {}

func (*Server_TrickleEvent) isServer_Payload() {}

func (*Server_PeersEvent) isServer_Payload() {}

func (*Server_JoinEvent) isServer_Payload() {}

func (*Server_BroadcastEvent) isServer_Payload() {}

func (m *Server) GetPayload() isServer_Payload {
	if m != nil {
		return m.Payload
	}
	return nil
}

func (m *Server) GetJoin() *JoinReply {
	if x, ok := m.GetPayload().(*Server_Join); ok {
		return x.Join
	}
	return nil
}

func (m *Server) GetOffer() *Offer {
	if x, ok := m.GetPayload().(*Server_Offer); ok {
		return x.Offer
	}
	return nil
}

func (m *Server) GetAnswer() *Answer {
	if x, ok := m.GetPayload().(*Server_Answer); ok {
		return x.Answer
	}
	return nil
}

func (m *Server) GetTrickleEvent() *Trickle {
	if x, ok := m.GetPayload().(*Server_TrickleEvent); ok {
		return x.TrickleEvent
	}
	return nil
}

func (m *Server) GetPeersEvent() *PeersEvent {
	if x, ok := m.GetPayload().(*Server_PeersEvent); ok {
		return x.PeersEvent
	}
	return nil
}

func (m *Server) GetJoinEvent() *JoinEvent {
	if x, ok := m.GetPayload().(*Server_JoinEvent); ok {
		return x.JoinEvent
	}
	return nil
}

func (m *Server) GetBroadcastEvent() *Broadcast {
	if x, ok := m.GetPayload().(*Server_BroadcastEvent); ok {
		return x.BroadcastEvent
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*Server) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*Server_Join)(nil),
		(*Server_Offer)(nil),
		(*Server_Answer)(nil),
		(*Server_TrickleEvent)(nil),
		(*Server_PeersEvent)(nil),
		(*Server_JoinEvent)(nil),
		(*Server_BroadcastEvent)(nil),
	}
}

type JoinRequest struct {
	Sid                  string   `protobuf:"bytes,1,opt,name=sid,proto3" json:"sid,omitempty"`
	Uid                  string   `protobuf:"bytes,2,opt,name=uid,proto3" json:"uid,omitempty"`
	Offer                []byte   `protobuf:"bytes,3,opt,name=offer,proto3" json:"offer,omitempty"`
	Token                string   `protobuf:"bytes,4,opt,name=token,proto3" json:"token,omitempty"`
	Info                 []byte   `protobuf:"bytes,5,opt,name=info,proto3" json:"info,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *JoinRequest) Reset()         { *m = JoinRequest{} }
func (m *JoinRequest) String() string { return proto.CompactTextString(m) }
func (*JoinRequest) ProtoMessage()    {}
func (*JoinRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_3def3f03f57c29b9, []int{2}
}

func (m *JoinRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_JoinRequest.Unmarshal(m, b)
}
func (m *JoinRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_JoinRequest.Marshal(b, m, deterministic)
}
func (m *JoinRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_JoinRequest.Merge(m, src)
}
func (m *JoinRequest) XXX_Size() int {
	return xxx_messageInfo_JoinRequest.Size(m)
}
func (m *JoinRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_JoinRequest.DiscardUnknown(m)
}

var xxx_messageInfo_JoinRequest proto.InternalMessageInfo

func (m *JoinRequest) GetSid() string {
	if m != nil {
		return m.Sid
	}
	return ""
}

func (m *JoinRequest) GetUid() string {
	if m != nil {
		return m.Uid
	}
	return ""
}

func (m *JoinRequest) GetOffer() []byte {
	if m != nil {
		return m.Offer
	}
	return nil
}

func (m *JoinRequest) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

func (m *JoinRequest) GetInfo() []byte {
	if m != nil {
		return m.Info
	}
	return nil
}

type LeaveRequest struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LeaveRequest) Reset()         { *m = LeaveRequest{} }
func (m *LeaveRequest) String() string { return proto.CompactTextString(m) }
func (*LeaveRequest) ProtoMessage()    {}
func (*LeaveRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_3def3f03f57c29b9, []int{3}
}

func (m *LeaveRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LeaveRequest.Unmarshal(m, b)
}
func (m *LeaveRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LeaveRequest.Marshal(b, m, deterministic)
}
func (m *LeaveRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LeaveRequest.Merge(m, src)
}
func (m *LeaveRequest) XXX_Size() int {
	return xxx_messageInfo_LeaveRequest.Size(m)
}
func (m *LeaveRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_LeaveRequest.DiscardUnknown(m)
}

var xxx_messageInfo_LeaveRequest proto.InternalMessageInfo

type BroadcastRequest struct {
	Info                 []byte   `protobuf:"bytes,1,opt,name=info,proto3" json:"info,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *BroadcastRequest) Reset()         { *m = BroadcastRequest{} }
func (m *BroadcastRequest) String() string { return proto.CompactTextString(m) }
func (*BroadcastRequest) ProtoMessage()    {}
func (*BroadcastRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_3def3f03f57c29b9, []int{4}
}

func (m *BroadcastRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BroadcastRequest.Unmarshal(m, b)
}
func (m *BroadcastRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BroadcastRequest.Marshal(b, m, deterministic)
}
func (m *BroadcastRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BroadcastRequest.Merge(m, src)
}
func (m *BroadcastRequest) XXX_Size() int {
	return xxx_messageInfo_BroadcastRequest.Size(m)
}
func (m *BroadcastRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_BroadcastRequest.DiscardUnknown(m)
}

var xxx_messageInfo_BroadcastRequest proto.InternalMessageInfo

func (m *BroadcastRequest) GetInfo() []byte {
	if m != nil {
		return m.Info
	}
	return nil
}

type Offer struct {
	Desc                 []byte   `protobuf:"bytes,1,opt,name=desc,proto3" json:"desc,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Offer) Reset()         { *m = Offer{} }
func (m *Offer) String() string { return proto.CompactTextString(m) }
func (*Offer) ProtoMessage()    {}
func (*Offer) Descriptor() ([]byte, []int) {
	return fileDescriptor_3def3f03f57c29b9, []int{5}
}

func (m *Offer) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Offer.Unmarshal(m, b)
}
func (m *Offer) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Offer.Marshal(b, m, deterministic)
}
func (m *Offer) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Offer.Merge(m, src)
}
func (m *Offer) XXX_Size() int {
	return xxx_messageInfo_Offer.Size(m)
}
func (m *Offer) XXX_DiscardUnknown() {
	xxx_messageInfo_Offer.DiscardUnknown(m)
}

var xxx_messageInfo_Offer proto.InternalMessageInfo

func (m *Offer) GetDesc() []byte {
	if m != nil {
		return m.Desc
	}
	return nil
}

type Answer struct {
	Desc                 []byte   `protobuf:"bytes,1,opt,name=desc,proto3" json:"desc,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Answer) Reset()         { *m = Answer{} }
func (m *Answer) String() string { return proto.CompactTextString(m) }
func (*Answer) ProtoMessage()    {}
func (*Answer) Descriptor() ([]byte, []int) {
	return fileDescriptor_3def3f03f57c29b9, []int{6}
}

func (m *Answer) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Answer.Unmarshal(m, b)
}
func (m *Answer) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Answer.Marshal(b, m, deterministic)
}
func (m *Answer) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Answer.Merge(m, src)
}
func (m *Answer) XXX_Size() int {
	return xxx_messageInfo_Answer.Size(m)
}
func (m *Answer) XXX_DiscardUnknown() {
	xxx_messageInfo_Answer.DiscardUnknown(m)
}

var xxx_messageInfo_Answer proto.InternalMessageInfo

func (m *Answer) GetDesc() []byte {
	if m != nil {
		return m.Desc
	}
	return nil
}

type Trickle struct {
	Target               Trickle_Target `protobuf:"varint,1,opt,name=target,proto3,enum=biz.Trickle_Target" json:"target,omitempty"`
	Candidate            string         `protobuf:"bytes,2,opt,name=candidate,proto3" json:"candidate,omitempty"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *Trickle) Reset()         { *m = Trickle{} }
func (m *Trickle) String() string { return proto.CompactTextString(m) }
func (*Trickle) ProtoMessage()    {}
func (*Trickle) Descriptor() ([]byte, []int) {
	return fileDescriptor_3def3f03f57c29b9, []int{7}
}

func (m *Trickle) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Trickle.Unmarshal(m, b)
}
func (m *Trickle) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Trickle.Marshal(b, m, deterministic)
}
func (m *Trickle) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Trickle.Merge(m, src)
}
func (m *Trickle) XXX_Size() int {
	return xxx_messageInfo_Trickle.Size(m)
}
func (m *Trickle) XXX_DiscardUnknown() {
	xxx_messageInfo_Trickle.DiscardUnknown(m)
}

var xxx_messageInfo_Trickle proto.InternalMessageInfo

func (m *Trickle) GetTarget() Trickle_Target {
	if m != nil {
		return m.Target
	}
	return Trickle_PUBLISHER
}

func (m *Trickle) GetCandidate() string {
	if m != nil {
		return m.Candidate
	}
	return ""
}

type Broadcast struct {
	Sid                  string   `protobuf:"bytes,1,opt,name=sid,proto3" json:"sid,omitempty"`
	Uid                  string   `protobuf:"bytes,2,opt,name=uid,proto3" json:"uid,omitempty"`
	Info                 []byte   `protobuf:"bytes,3,opt,name=info,proto3" json:"info,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Broadcast) Reset()         { *m = Broadcast{} }
func (m *Broadcast) String() string { return proto.CompactTextString(m) }
func (*Broadcast) ProtoMessage()    {}
func (*Broadcast) Descriptor() ([]byte, []int) {
	return fileDescriptor_3def3f03f57c29b9, []int{8}
}

func (m *Broadcast) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Broadcast.Unmarshal(m, b)
}
func (m *Broadcast) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Broadcast.Marshal(b, m, deterministic)
}
func (m *Broadcast) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Broadcast.Merge(m, src)
}
func (m *Broadcast) XXX_Size() int {
	return xxx_messageInfo_Broadcast.Size(m)
}
func (m *Broadcast) XXX_DiscardUnknown() {
	xxx_messageInfo_Broadcast.DiscardUnknown(m)
}

var xxx_messageInfo_Broadcast proto.InternalMessageInfo

func (m *Broadcast) GetSid() string {
	if m != nil {
		return m.Sid
	}
	return ""
}

func (m *Broadcast) GetUid() string {
	if m != nil {
		return m.Uid
	}
	return ""
}

func (m *Broadcast) GetInfo() []byte {
	if m != nil {
		return m.Info
	}
	return nil
}

type JoinReply struct {
	Answer               []byte   `protobuf:"bytes,1,opt,name=answer,proto3" json:"answer,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *JoinReply) Reset()         { *m = JoinReply{} }
func (m *JoinReply) String() string { return proto.CompactTextString(m) }
func (*JoinReply) ProtoMessage()    {}
func (*JoinReply) Descriptor() ([]byte, []int) {
	return fileDescriptor_3def3f03f57c29b9, []int{9}
}

func (m *JoinReply) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_JoinReply.Unmarshal(m, b)
}
func (m *JoinReply) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_JoinReply.Marshal(b, m, deterministic)
}
func (m *JoinReply) XXX_Merge(src proto.Message) {
	xxx_messageInfo_JoinReply.Merge(m, src)
}
func (m *JoinReply) XXX_Size() int {
	return xxx_messageInfo_JoinReply.Size(m)
}
func (m *JoinReply) XXX_DiscardUnknown() {
	xxx_messageInfo_JoinReply.DiscardUnknown(m)
}

var xxx_messageInfo_JoinReply proto.InternalMessageInfo

func (m *JoinReply) GetAnswer() []byte {
	if m != nil {
		return m.Answer
	}
	return nil
}

type Peer struct {
	Uid                  string   `protobuf:"bytes,1,opt,name=uid,proto3" json:"uid,omitempty"`
	Info                 []byte   `protobuf:"bytes,2,opt,name=info,proto3" json:"info,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Peer) Reset()         { *m = Peer{} }
func (m *Peer) String() string { return proto.CompactTextString(m) }
func (*Peer) ProtoMessage()    {}
func (*Peer) Descriptor() ([]byte, []int) {
	return fileDescriptor_3def3f03f57c29b9, []int{10}
}

func (m *Peer) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Peer.Unmarshal(m, b)
}
func (m *Peer) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Peer.Marshal(b, m, deterministic)
}
func (m *Peer) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Peer.Merge(m, src)
}
func (m *Peer) XXX_Size() int {
	return xxx_messageInfo_Peer.Size(m)
}
func (m *Peer) XXX_DiscardUnknown() {
	xxx_messageInfo_Peer.DiscardUnknown(m)
}

var xxx_messageInfo_Peer proto.InternalMessageInfo

func (m *Peer) GetUid() string {
	if m != nil {
		return m.Uid
	}
	return ""
}

func (m *Peer) GetInfo() []byte {
	if m != nil {
		return m.Info
	}
	return nil
}

type Stream struct {
	Sid                  string   `protobuf:"bytes,1,opt,name=sid,proto3" json:"sid,omitempty"`
	Uid                  string   `protobuf:"bytes,2,opt,name=uid,proto3" json:"uid,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Stream) Reset()         { *m = Stream{} }
func (m *Stream) String() string { return proto.CompactTextString(m) }
func (*Stream) ProtoMessage()    {}
func (*Stream) Descriptor() ([]byte, []int) {
	return fileDescriptor_3def3f03f57c29b9, []int{11}
}

func (m *Stream) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Stream.Unmarshal(m, b)
}
func (m *Stream) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Stream.Marshal(b, m, deterministic)
}
func (m *Stream) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Stream.Merge(m, src)
}
func (m *Stream) XXX_Size() int {
	return xxx_messageInfo_Stream.Size(m)
}
func (m *Stream) XXX_DiscardUnknown() {
	xxx_messageInfo_Stream.DiscardUnknown(m)
}

var xxx_messageInfo_Stream proto.InternalMessageInfo

func (m *Stream) GetSid() string {
	if m != nil {
		return m.Sid
	}
	return ""
}

func (m *Stream) GetUid() string {
	if m != nil {
		return m.Uid
	}
	return ""
}

type PeersEvent struct {
	Peers                []*Peer   `protobuf:"bytes,1,rep,name=peers,proto3" json:"peers,omitempty"`
	Streams              []*Stream `protobuf:"bytes,2,rep,name=streams,proto3" json:"streams,omitempty"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *PeersEvent) Reset()         { *m = PeersEvent{} }
func (m *PeersEvent) String() string { return proto.CompactTextString(m) }
func (*PeersEvent) ProtoMessage()    {}
func (*PeersEvent) Descriptor() ([]byte, []int) {
	return fileDescriptor_3def3f03f57c29b9, []int{12}
}

func (m *PeersEvent) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PeersEvent.Unmarshal(m, b)
}
func (m *PeersEvent) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PeersEvent.Marshal(b, m, deterministic)
}
func (m *PeersEvent) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PeersEvent.Merge(m, src)
}
func (m *PeersEvent) XXX_Size() int {
	return xxx_messageInfo_PeersEvent.Size(m)
}
func (m *PeersEvent) XXX_DiscardUnknown() {
	xxx_messageInfo_PeersEvent.DiscardUnknown(m)
}

var xxx_messageInfo_PeersEvent proto.InternalMessageInfo

func (m *PeersEvent) GetPeers() []*Peer {
	if m != nil {
		return m.Peers
	}
	return nil
}

func (m *PeersEvent) GetStreams() []*Stream {
	if m != nil {
		return m.Streams
	}
	return nil
}

type JoinEvent struct {
	Uid                  string   `protobuf:"bytes,1,opt,name=uid,proto3" json:"uid,omitempty"`
	Sid                  string   `protobuf:"bytes,2,opt,name=sid,proto3" json:"sid,omitempty"`
	Info                 []byte   `protobuf:"bytes,3,opt,name=info,proto3" json:"info,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *JoinEvent) Reset()         { *m = JoinEvent{} }
func (m *JoinEvent) String() string { return proto.CompactTextString(m) }
func (*JoinEvent) ProtoMessage()    {}
func (*JoinEvent) Descriptor() ([]byte, []int) {
	return fileDescriptor_3def3f03f57c29b9, []int{13}
}

func (m *JoinEvent) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_JoinEvent.Unmarshal(m, b)
}
func (m *JoinEvent) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_JoinEvent.Marshal(b, m, deterministic)
}
func (m *JoinEvent) XXX_Merge(src proto.Message) {
	xxx_messageInfo_JoinEvent.Merge(m, src)
}
func (m *JoinEvent) XXX_Size() int {
	return xxx_messageInfo_JoinEvent.Size(m)
}
func (m *JoinEvent) XXX_DiscardUnknown() {
	xxx_messageInfo_JoinEvent.DiscardUnknown(m)
}

var xxx_messageInfo_JoinEvent proto.InternalMessageInfo

func (m *JoinEvent) GetUid() string {
	if m != nil {
		return m.Uid
	}
	return ""
}

func (m *JoinEvent) GetSid() string {
	if m != nil {
		return m.Sid
	}
	return ""
}

func (m *JoinEvent) GetInfo() []byte {
	if m != nil {
		return m.Info
	}
	return nil
}

func init() {
	proto.RegisterEnum("biz.Trickle_Target", Trickle_Target_name, Trickle_Target_value)
	proto.RegisterType((*Client)(nil), "biz.Client")
	proto.RegisterType((*Server)(nil), "biz.Server")
	proto.RegisterType((*JoinRequest)(nil), "biz.JoinRequest")
	proto.RegisterType((*LeaveRequest)(nil), "biz.LeaveRequest")
	proto.RegisterType((*BroadcastRequest)(nil), "biz.BroadcastRequest")
	proto.RegisterType((*Offer)(nil), "biz.Offer")
	proto.RegisterType((*Answer)(nil), "biz.Answer")
	proto.RegisterType((*Trickle)(nil), "biz.Trickle")
	proto.RegisterType((*Broadcast)(nil), "biz.Broadcast")
	proto.RegisterType((*JoinReply)(nil), "biz.JoinReply")
	proto.RegisterType((*Peer)(nil), "biz.Peer")
	proto.RegisterType((*Stream)(nil), "biz.Stream")
	proto.RegisterType((*PeersEvent)(nil), "biz.PeersEvent")
	proto.RegisterType((*JoinEvent)(nil), "biz.JoinEvent")
}

func init() { proto.RegisterFile("cmd/biz/grpc/proto/biz.proto", fileDescriptor_3def3f03f57c29b9) }

var fileDescriptor_3def3f03f57c29b9 = []byte{
	// 648 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x94, 0x4d, 0x4f, 0xdb, 0x4c,
	0x10, 0xc7, 0xfd, 0x92, 0x38, 0x8f, 0x27, 0x79, 0xdc, 0x74, 0x8a, 0x2a, 0x8b, 0x22, 0x15, 0xb9,
	0x85, 0xa6, 0x2a, 0x4a, 0xda, 0xf4, 0x52, 0xa9, 0xa7, 0x1a, 0x21, 0x85, 0x0a, 0xa9, 0x68, 0x03,
	0x17, 0x6e, 0x8e, 0xbd, 0xa0, 0x2d, 0xc6, 0x0e, 0xb6, 0xa1, 0x02, 0xa9, 0x1f, 0xa5, 0x1f, 0xaf,
	0xdf, 0xa3, 0xda, 0x59, 0xbf, 0x01, 0x69, 0xc5, 0x25, 0x99, 0x9d, 0xf9, 0xcd, 0xee, 0xcc, 0x7f,
	0xc7, 0x0b, 0x1b, 0xe1, 0x45, 0x34, 0x59, 0x88, 0xdb, 0xc9, 0x59, 0xb6, 0x0c, 0x27, 0xcb, 0x2c,
	0x2d, 0x52, 0xb9, 0x1c, 0x93, 0x85, 0xe6, 0x42, 0xdc, 0x7a, 0xbf, 0x0c, 0xb0, 0x76, 0x63, 0xc1,
	0x93, 0x02, 0x87, 0x60, 0xe6, 0x22, 0x72, 0xf5, 0x4d, 0x7d, 0x64, 0x33, 0x69, 0xe2, 0x36, 0x74,
	0xbe, 0xa7, 0x22, 0x71, 0x8d, 0x4d, 0x7d, 0xd4, 0x9f, 0x0e, 0xc7, 0x32, 0xf7, 0x6b, 0x2a, 0x12,
	0xc6, 0x2f, 0xaf, 0x78, 0x5e, 0xcc, 0x34, 0x46, 0x71, 0x7c, 0x0b, 0xdd, 0x98, 0x07, 0xd7, 0xdc,
	0x35, 0x09, 0x7c, 0x4a, 0xe0, 0x81, 0xf4, 0x34, 0xa4, 0x22, 0xd0, 0x83, 0x6e, 0x7a, 0x7a, 0xca,
	0x33, 0xb7, 0x43, 0x28, 0x10, 0xfa, 0x4d, 0x7a, 0x24, 0x43, 0x21, 0xdc, 0x02, 0x2b, 0x48, 0xf2,
	0x1f, 0x3c, 0x73, 0xbb, 0x04, 0xf5, 0x09, 0xfa, 0x42, 0xae, 0x99, 0xc6, 0xca, 0x20, 0x8e, 0xa0,
	0x57, 0x64, 0x22, 0x3c, 0x8f, 0xb9, 0x6b, 0x11, 0x37, 0x20, 0xee, 0x48, 0xf9, 0x66, 0x1a, 0xab,
	0xc2, 0x38, 0x06, 0x7b, 0x91, 0xa5, 0x41, 0x14, 0x06, 0x79, 0xe1, 0xf6, 0x88, 0x75, 0x88, 0xf5,
	0x2b, 0xef, 0x4c, 0x63, 0x0d, 0xe2, 0xdb, 0xd0, 0x5b, 0x06, 0x37, 0x71, 0x1a, 0x44, 0xde, 0x6f,
	0x03, 0xac, 0x39, 0xcf, 0xae, 0x79, 0x86, 0x0e, 0x18, 0xb5, 0x3c, 0x86, 0x88, 0xf0, 0xf5, 0x1d,
	0x75, 0x9c, 0x96, 0x3a, 0xcb, 0xf8, 0xa6, 0xd6, 0xa6, 0x6e, 0xd8, 0x7c, 0x4c, 0xc3, 0x9d, 0x7f,
	0x35, 0x3c, 0x85, 0x41, 0xd9, 0xd1, 0xde, 0x35, 0x4f, 0x8a, 0x52, 0x9d, 0xfb, 0x5d, 0xdf, 0x61,
	0xf0, 0x03, 0xc0, 0x92, 0xf3, 0x2c, 0x57, 0x19, 0x4a, 0xa7, 0x27, 0x94, 0x71, 0x58, 0xbb, 0x67,
	0x1a, 0x6b, 0x41, 0x52, 0x2d, 0x59, 0xb9, 0xca, 0xe8, 0xdd, 0x6b, 0xae, 0x4a, 0x68, 0x10, 0xfc,
	0x04, 0x4e, 0x2d, 0x9d, 0x4a, 0xfa, 0xef, 0x2f, 0x12, 0xdf, 0xe3, 0xda, 0x3a, 0x5f, 0x42, 0xbf,
	0x35, 0x59, 0x2b, 0x66, 0x71, 0x08, 0xe6, 0x95, 0x88, 0x48, 0x6c, 0x9b, 0x49, 0x13, 0xd7, 0xda,
	0xca, 0x0e, 0x2a, 0x2d, 0xd7, 0xa0, 0x5b, 0xa4, 0xe7, 0x3c, 0x21, 0x29, 0x6d, 0xa6, 0x16, 0x88,
	0xd0, 0x11, 0xc9, 0x69, 0x4a, 0x92, 0x0d, 0x18, 0xd9, 0x9e, 0x03, 0x83, 0xf6, 0x8c, 0x7a, 0xdb,
	0x30, 0xac, 0x8b, 0xad, 0xea, 0xa8, 0xf2, 0xf4, 0x56, 0xde, 0x0b, 0xe8, 0xd2, 0xfd, 0xc9, 0x60,
	0xc4, 0xf3, 0xb0, 0x0a, 0x4a, 0xdb, 0xdb, 0x00, 0x4b, 0xdd, 0xdb, 0xca, 0xe8, 0x4f, 0xe8, 0x95,
	0x17, 0x85, 0xef, 0xc0, 0x2a, 0x82, 0xec, 0x8c, 0x17, 0x04, 0x38, 0xd3, 0x67, 0xed, 0x6b, 0x1c,
	0x1f, 0x51, 0x88, 0x95, 0x08, 0x6e, 0x80, 0x1d, 0x06, 0x49, 0x24, 0xa2, 0xa0, 0xe0, 0xa5, 0x04,
	0x8d, 0xc3, 0x7b, 0x03, 0x96, 0xe2, 0xf1, 0x7f, 0xb0, 0x0f, 0x8f, 0xfd, 0x83, 0xfd, 0xf9, 0x6c,
	0x8f, 0x0d, 0x35, 0x74, 0x00, 0xe6, 0xc7, 0xfe, 0x7c, 0x97, 0xed, 0xfb, 0x7b, 0x6c, 0xa8, 0x7b,
	0xbb, 0x60, 0xd7, 0x1d, 0x3e, 0x4a, 0xe2, 0xaa, 0x7d, 0xb3, 0xd5, 0xfe, 0x2b, 0xb0, 0xeb, 0x29,
	0xc7, 0xe7, 0xf5, 0xe4, 0xaa, 0x36, 0xcb, 0x95, 0xb7, 0x03, 0x1d, 0x39, 0x5f, 0xd5, 0x96, 0xfa,
	0xc3, 0x2d, 0x8d, 0xd6, 0x96, 0x3b, 0x60, 0xcd, 0x8b, 0x8c, 0x07, 0x17, 0x8f, 0x29, 0xca, 0x3b,
	0x02, 0x68, 0x66, 0x17, 0x5f, 0x42, 0x97, 0x66, 0xd7, 0xd5, 0x37, 0xcd, 0x51, 0x7f, 0x6a, 0xd7,
	0xb3, 0xcd, 0x94, 0x1f, 0xb7, 0xa0, 0x97, 0xd3, 0xe6, 0xb9, 0x6b, 0x10, 0xa2, 0xbe, 0x2e, 0x75,
	0x20, 0xab, 0x62, 0x52, 0x9b, 0x7a, 0xbe, 0x57, 0x94, 0x5d, 0x16, 0x66, 0x34, 0x85, 0xad, 0xd0,
	0x66, 0x3a, 0x01, 0xd3, 0xdf, 0x3f, 0xc1, 0x11, 0x58, 0x73, 0x71, 0x96, 0x04, 0x31, 0xaa, 0xb3,
	0xd4, 0x03, 0xbb, 0x5e, 0x1e, 0x4c, 0xaf, 0x89, 0xa7, 0x8d, 0xf4, 0xf7, 0xba, 0xbf, 0x7e, 0xe2,
	0x3e, 0x7c, 0xa3, 0x3f, 0xd3, 0xef, 0xc2, 0xa2, 0xbf, 0x8f, 0x7f, 0x02, 0x00, 0x00, 0xff, 0xff,
	0xaf, 0xbb, 0x20, 0x26, 0xc6, 0x05, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// BIZClient is the client API for BIZ service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type BIZClient interface {
	Signal(ctx context.Context, opts ...grpc.CallOption) (BIZ_SignalClient, error)
}

type bIZClient struct {
	cc *grpc.ClientConn
}

func NewBIZClient(cc *grpc.ClientConn) BIZClient {
	return &bIZClient{cc}
}

func (c *bIZClient) Signal(ctx context.Context, opts ...grpc.CallOption) (BIZ_SignalClient, error) {
	stream, err := c.cc.NewStream(ctx, &_BIZ_serviceDesc.Streams[0], "/biz.BIZ/Signal", opts...)
	if err != nil {
		return nil, err
	}
	x := &bIZSignalClient{stream}
	return x, nil
}

type BIZ_SignalClient interface {
	Send(*Client) error
	Recv() (*Server, error)
	grpc.ClientStream
}

type bIZSignalClient struct {
	grpc.ClientStream
}

func (x *bIZSignalClient) Send(m *Client) error {
	return x.ClientStream.SendMsg(m)
}

func (x *bIZSignalClient) Recv() (*Server, error) {
	m := new(Server)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// BIZServer is the server API for BIZ service.
type BIZServer interface {
	Signal(BIZ_SignalServer) error
}

// UnimplementedBIZServer can be embedded to have forward compatible implementations.
type UnimplementedBIZServer struct {
}

func (*UnimplementedBIZServer) Signal(srv BIZ_SignalServer) error {
	return status.Errorf(codes.Unimplemented, "method Signal not implemented")
}

func RegisterBIZServer(s *grpc.Server, srv BIZServer) {
	s.RegisterService(&_BIZ_serviceDesc, srv)
}

func _BIZ_Signal_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(BIZServer).Signal(&bIZSignalServer{stream})
}

type BIZ_SignalServer interface {
	Send(*Server) error
	Recv() (*Client, error)
	grpc.ServerStream
}

type bIZSignalServer struct {
	grpc.ServerStream
}

func (x *bIZSignalServer) Send(m *Server) error {
	return x.ServerStream.SendMsg(m)
}

func (x *bIZSignalServer) Recv() (*Client, error) {
	m := new(Client)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

var _BIZ_serviceDesc = grpc.ServiceDesc{
	ServiceName: "biz.BIZ",
	HandlerType: (*BIZServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Signal",
			Handler:       _BIZ_Signal_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "cmd/biz/grpc/proto/biz.proto",
}
