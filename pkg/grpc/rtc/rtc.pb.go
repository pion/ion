// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0-devel
// 	protoc        v3.12.2
// source: protos/rtc.proto

package rtc

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Target int32

const (
	Target_PUBLISHER  Target = 0
	Target_SUBSCRIBER Target = 1
)

// Enum value maps for Target.
var (
	Target_name = map[int32]string{
		0: "PUBLISHER",
		1: "SUBSCRIBER",
	}
	Target_value = map[string]int32{
		"PUBLISHER":  0,
		"SUBSCRIBER": 1,
	}
)

func (x Target) Enum() *Target {
	p := new(Target)
	*p = x
	return p
}

func (x Target) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Target) Descriptor() protoreflect.EnumDescriptor {
	return file_protos_rtc_proto_enumTypes[0].Descriptor()
}

func (Target) Type() protoreflect.EnumType {
	return &file_protos_rtc_proto_enumTypes[0]
}

func (x Target) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Target.Descriptor instead.
func (Target) EnumDescriptor() ([]byte, []int) {
	return file_protos_rtc_proto_rawDescGZIP(), []int{0}
}

type Parameter struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key   string `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Value string `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *Parameter) Reset() {
	*x = Parameter{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protos_rtc_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Parameter) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Parameter) ProtoMessage() {}

func (x *Parameter) ProtoReflect() protoreflect.Message {
	mi := &file_protos_rtc_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Parameter.ProtoReflect.Descriptor instead.
func (*Parameter) Descriptor() ([]byte, []int) {
	return file_protos_rtc_proto_rawDescGZIP(), []int{0}
}

func (x *Parameter) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *Parameter) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

type JoinRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Sid        string       `protobuf:"bytes,1,opt,name=sid,proto3" json:"sid,omitempty"`
	Uid        string       `protobuf:"bytes,2,opt,name=uid,proto3" json:"uid,omitempty"`
	Parameters []*Parameter `protobuf:"bytes,3,rep,name=parameters,proto3" json:"parameters,omitempty"`
}

func (x *JoinRequest) Reset() {
	*x = JoinRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protos_rtc_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *JoinRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*JoinRequest) ProtoMessage() {}

func (x *JoinRequest) ProtoReflect() protoreflect.Message {
	mi := &file_protos_rtc_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use JoinRequest.ProtoReflect.Descriptor instead.
func (*JoinRequest) Descriptor() ([]byte, []int) {
	return file_protos_rtc_proto_rawDescGZIP(), []int{1}
}

func (x *JoinRequest) GetSid() string {
	if x != nil {
		return x.Sid
	}
	return ""
}

func (x *JoinRequest) GetUid() string {
	if x != nil {
		return x.Uid
	}
	return ""
}

func (x *JoinRequest) GetParameters() []*Parameter {
	if x != nil {
		return x.Parameters
	}
	return nil
}

type JoinReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Success bool   `protobuf:"varint,1,opt,name=success,proto3" json:"success,omitempty"`
	Error   string `protobuf:"bytes,2,opt,name=error,proto3" json:"error,omitempty"` // room is full ?
}

func (x *JoinReply) Reset() {
	*x = JoinReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protos_rtc_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *JoinReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*JoinReply) ProtoMessage() {}

func (x *JoinReply) ProtoReflect() protoreflect.Message {
	mi := &file_protos_rtc_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use JoinReply.ProtoReflect.Descriptor instead.
func (*JoinReply) Descriptor() ([]byte, []int) {
	return file_protos_rtc_proto_rawDescGZIP(), []int{2}
}

func (x *JoinReply) GetSuccess() bool {
	if x != nil {
		return x.Success
	}
	return false
}

func (x *JoinReply) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

type Join struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Payload:
	//	*Join_Req
	//	*Join_Reply
	Payload isJoin_Payload `protobuf_oneof:"payload"`
}

func (x *Join) Reset() {
	*x = Join{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protos_rtc_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Join) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Join) ProtoMessage() {}

func (x *Join) ProtoReflect() protoreflect.Message {
	mi := &file_protos_rtc_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Join.ProtoReflect.Descriptor instead.
func (*Join) Descriptor() ([]byte, []int) {
	return file_protos_rtc_proto_rawDescGZIP(), []int{3}
}

func (m *Join) GetPayload() isJoin_Payload {
	if m != nil {
		return m.Payload
	}
	return nil
}

func (x *Join) GetReq() *JoinRequest {
	if x, ok := x.GetPayload().(*Join_Req); ok {
		return x.Req
	}
	return nil
}

func (x *Join) GetReply() *JoinReply {
	if x, ok := x.GetPayload().(*Join_Reply); ok {
		return x.Reply
	}
	return nil
}

type isJoin_Payload interface {
	isJoin_Payload()
}

type Join_Req struct {
	Req *JoinRequest `protobuf:"bytes,1,opt,name=req,proto3,oneof"`
}

type Join_Reply struct {
	Reply *JoinReply `protobuf:"bytes,2,opt,name=reply,proto3,oneof"`
}

func (*Join_Req) isJoin_Payload() {}

func (*Join_Reply) isJoin_Payload() {}

type Signalling struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Payload:
	//	*Signalling_Join
	//	*Signalling_Description
	//	*Signalling_Trickle
	//	*Signalling_Error
	Payload isSignalling_Payload `protobuf_oneof:"payload"`
}

func (x *Signalling) Reset() {
	*x = Signalling{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protos_rtc_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Signalling) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Signalling) ProtoMessage() {}

func (x *Signalling) ProtoReflect() protoreflect.Message {
	mi := &file_protos_rtc_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Signalling.ProtoReflect.Descriptor instead.
func (*Signalling) Descriptor() ([]byte, []int) {
	return file_protos_rtc_proto_rawDescGZIP(), []int{4}
}

func (m *Signalling) GetPayload() isSignalling_Payload {
	if m != nil {
		return m.Payload
	}
	return nil
}

func (x *Signalling) GetJoin() *Join {
	if x, ok := x.GetPayload().(*Signalling_Join); ok {
		return x.Join
	}
	return nil
}

func (x *Signalling) GetDescription() *Description {
	if x, ok := x.GetPayload().(*Signalling_Description); ok {
		return x.Description
	}
	return nil
}

func (x *Signalling) GetTrickle() *Trickle {
	if x, ok := x.GetPayload().(*Signalling_Trickle); ok {
		return x.Trickle
	}
	return nil
}

func (x *Signalling) GetError() *Error {
	if x, ok := x.GetPayload().(*Signalling_Error); ok {
		return x.Error
	}
	return nil
}

type isSignalling_Payload interface {
	isSignalling_Payload()
}

type Signalling_Join struct {
	Join *Join `protobuf:"bytes,1,opt,name=join,proto3,oneof"`
}

type Signalling_Description struct {
	Description *Description `protobuf:"bytes,2,opt,name=description,proto3,oneof"`
}

type Signalling_Trickle struct {
	Trickle *Trickle `protobuf:"bytes,3,opt,name=trickle,proto3,oneof"`
}

type Signalling_Error struct {
	Error *Error `protobuf:"bytes,4,opt,name=error,proto3,oneof"`
}

func (*Signalling_Join) isSignalling_Payload() {}

func (*Signalling_Description) isSignalling_Payload() {}

func (*Signalling_Trickle) isSignalling_Payload() {}

func (*Signalling_Error) isSignalling_Payload() {}

type Description struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id          string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Target      Target `protobuf:"varint,2,opt,name=target,proto3,enum=rtc.Target" json:"target,omitempty"`
	Description []byte `protobuf:"bytes,3,opt,name=description,proto3" json:"description,omitempty"`
}

func (x *Description) Reset() {
	*x = Description{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protos_rtc_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Description) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Description) ProtoMessage() {}

func (x *Description) ProtoReflect() protoreflect.Message {
	mi := &file_protos_rtc_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Description.ProtoReflect.Descriptor instead.
func (*Description) Descriptor() ([]byte, []int) {
	return file_protos_rtc_proto_rawDescGZIP(), []int{5}
}

func (x *Description) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Description) GetTarget() Target {
	if x != nil {
		return x.Target
	}
	return Target_PUBLISHER
}

func (x *Description) GetDescription() []byte {
	if x != nil {
		return x.Description
	}
	return nil
}

type Trickle struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id        string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Target    Target `protobuf:"varint,2,opt,name=target,proto3,enum=rtc.Target" json:"target,omitempty"`
	Candidate []byte `protobuf:"bytes,3,opt,name=candidate,proto3" json:"candidate,omitempty"`
}

func (x *Trickle) Reset() {
	*x = Trickle{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protos_rtc_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Trickle) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Trickle) ProtoMessage() {}

func (x *Trickle) ProtoReflect() protoreflect.Message {
	mi := &file_protos_rtc_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Trickle.ProtoReflect.Descriptor instead.
func (*Trickle) Descriptor() ([]byte, []int) {
	return file_protos_rtc_proto_rawDescGZIP(), []int{6}
}

func (x *Trickle) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Trickle) GetTarget() Target {
	if x != nil {
		return x.Target
	}
	return Target_PUBLISHER
}

func (x *Trickle) GetCandidate() []byte {
	if x != nil {
		return x.Candidate
	}
	return nil
}

type Error struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Code   int32  `protobuf:"varint,1,opt,name=code,proto3" json:"code,omitempty"`
	Reason string `protobuf:"bytes,2,opt,name=reason,proto3" json:"reason,omitempty"`
}

func (x *Error) Reset() {
	*x = Error{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protos_rtc_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Error) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Error) ProtoMessage() {}

func (x *Error) ProtoReflect() protoreflect.Message {
	mi := &file_protos_rtc_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Error.ProtoReflect.Descriptor instead.
func (*Error) Descriptor() ([]byte, []int) {
	return file_protos_rtc_proto_rawDescGZIP(), []int{7}
}

func (x *Error) GetCode() int32 {
	if x != nil {
		return x.Code
	}
	return 0
}

func (x *Error) GetReason() string {
	if x != nil {
		return x.Reason
	}
	return ""
}

var File_protos_rtc_proto protoreflect.FileDescriptor

var file_protos_rtc_proto_rawDesc = []byte{
	0x0a, 0x10, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2f, 0x72, 0x74, 0x63, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x03, 0x72, 0x74, 0x63, 0x22, 0x33, 0x0a, 0x09, 0x50, 0x61, 0x72, 0x61, 0x6d,
	0x65, 0x74, 0x65, 0x72, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x22, 0x61, 0x0a, 0x0b,
	0x4a, 0x6f, 0x69, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x73,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x73, 0x69, 0x64, 0x12, 0x10, 0x0a,
	0x03, 0x75, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x75, 0x69, 0x64, 0x12,
	0x2e, 0x0a, 0x0a, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x73, 0x18, 0x03, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x72, 0x74, 0x63, 0x2e, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x65,
	0x74, 0x65, 0x72, 0x52, 0x0a, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x73, 0x22,
	0x3b, 0x0a, 0x09, 0x4a, 0x6f, 0x69, 0x6e, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x12, 0x18, 0x0a, 0x07,
	0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x73,
	0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x22, 0x5f, 0x0a, 0x04,
	0x4a, 0x6f, 0x69, 0x6e, 0x12, 0x24, 0x0a, 0x03, 0x72, 0x65, 0x71, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x10, 0x2e, 0x72, 0x74, 0x63, 0x2e, 0x4a, 0x6f, 0x69, 0x6e, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x48, 0x00, 0x52, 0x03, 0x72, 0x65, 0x71, 0x12, 0x26, 0x0a, 0x05, 0x72, 0x65,
	0x70, 0x6c, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x72, 0x74, 0x63, 0x2e,
	0x4a, 0x6f, 0x69, 0x6e, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x48, 0x00, 0x52, 0x05, 0x72, 0x65, 0x70,
	0x6c, 0x79, 0x42, 0x09, 0x0a, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x22, 0xbc, 0x01,
	0x0a, 0x0a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x6c, 0x69, 0x6e, 0x67, 0x12, 0x1f, 0x0a, 0x04,
	0x6a, 0x6f, 0x69, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x09, 0x2e, 0x72, 0x74, 0x63,
	0x2e, 0x4a, 0x6f, 0x69, 0x6e, 0x48, 0x00, 0x52, 0x04, 0x6a, 0x6f, 0x69, 0x6e, 0x12, 0x34, 0x0a,
	0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x10, 0x2e, 0x72, 0x74, 0x63, 0x2e, 0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x48, 0x00, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x12, 0x28, 0x0a, 0x07, 0x74, 0x72, 0x69, 0x63, 0x6b, 0x6c, 0x65, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x72, 0x74, 0x63, 0x2e, 0x54, 0x72, 0x69, 0x63, 0x6b,
	0x6c, 0x65, 0x48, 0x00, 0x52, 0x07, 0x74, 0x72, 0x69, 0x63, 0x6b, 0x6c, 0x65, 0x12, 0x22, 0x0a,
	0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x72,
	0x74, 0x63, 0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x48, 0x00, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f,
	0x72, 0x42, 0x09, 0x0a, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x22, 0x64, 0x0a, 0x0b,
	0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x0e, 0x0a, 0x02, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x23, 0x0a, 0x06, 0x74,
	0x61, 0x72, 0x67, 0x65, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0b, 0x2e, 0x72, 0x74,
	0x63, 0x2e, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x52, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74,
	0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69,
	0x6f, 0x6e, 0x22, 0x5c, 0x0a, 0x07, 0x54, 0x72, 0x69, 0x63, 0x6b, 0x6c, 0x65, 0x12, 0x0e, 0x0a,
	0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x23, 0x0a,
	0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0b, 0x2e,
	0x72, 0x74, 0x63, 0x2e, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x52, 0x06, 0x74, 0x61, 0x72, 0x67,
	0x65, 0x74, 0x12, 0x1c, 0x0a, 0x09, 0x63, 0x61, 0x6e, 0x64, 0x69, 0x64, 0x61, 0x74, 0x65, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x63, 0x61, 0x6e, 0x64, 0x69, 0x64, 0x61, 0x74, 0x65,
	0x22, 0x33, 0x0a, 0x05, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x12, 0x0a, 0x04, 0x63, 0x6f, 0x64,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x12, 0x16, 0x0a,
	0x06, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x72,
	0x65, 0x61, 0x73, 0x6f, 0x6e, 0x2a, 0x27, 0x0a, 0x06, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x12,
	0x0d, 0x0a, 0x09, 0x50, 0x55, 0x42, 0x4c, 0x49, 0x53, 0x48, 0x45, 0x52, 0x10, 0x00, 0x12, 0x0e,
	0x0a, 0x0a, 0x53, 0x55, 0x42, 0x53, 0x43, 0x52, 0x49, 0x42, 0x45, 0x52, 0x10, 0x01, 0x32, 0x37,
	0x0a, 0x03, 0x52, 0x54, 0x43, 0x12, 0x30, 0x0a, 0x06, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x12,
	0x0f, 0x2e, 0x72, 0x74, 0x63, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x6c, 0x69, 0x6e, 0x67,
	0x1a, 0x0f, 0x2e, 0x72, 0x74, 0x63, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x6c, 0x69, 0x6e,
	0x67, 0x22, 0x00, 0x28, 0x01, 0x30, 0x01, 0x42, 0x22, 0x5a, 0x20, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x69, 0x6f, 0x6e, 0x2f, 0x69, 0x6f, 0x6e, 0x2f, 0x70,
	0x6b, 0x67, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x72, 0x74, 0x63, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_protos_rtc_proto_rawDescOnce sync.Once
	file_protos_rtc_proto_rawDescData = file_protos_rtc_proto_rawDesc
)

func file_protos_rtc_proto_rawDescGZIP() []byte {
	file_protos_rtc_proto_rawDescOnce.Do(func() {
		file_protos_rtc_proto_rawDescData = protoimpl.X.CompressGZIP(file_protos_rtc_proto_rawDescData)
	})
	return file_protos_rtc_proto_rawDescData
}

var file_protos_rtc_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_protos_rtc_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_protos_rtc_proto_goTypes = []interface{}{
	(Target)(0),         // 0: rtc.Target
	(*Parameter)(nil),   // 1: rtc.Parameter
	(*JoinRequest)(nil), // 2: rtc.JoinRequest
	(*JoinReply)(nil),   // 3: rtc.JoinReply
	(*Join)(nil),        // 4: rtc.Join
	(*Signalling)(nil),  // 5: rtc.Signalling
	(*Description)(nil), // 6: rtc.Description
	(*Trickle)(nil),     // 7: rtc.Trickle
	(*Error)(nil),       // 8: rtc.Error
}
var file_protos_rtc_proto_depIdxs = []int32{
	1,  // 0: rtc.JoinRequest.parameters:type_name -> rtc.Parameter
	2,  // 1: rtc.Join.req:type_name -> rtc.JoinRequest
	3,  // 2: rtc.Join.reply:type_name -> rtc.JoinReply
	4,  // 3: rtc.Signalling.join:type_name -> rtc.Join
	6,  // 4: rtc.Signalling.description:type_name -> rtc.Description
	7,  // 5: rtc.Signalling.trickle:type_name -> rtc.Trickle
	8,  // 6: rtc.Signalling.error:type_name -> rtc.Error
	0,  // 7: rtc.Description.target:type_name -> rtc.Target
	0,  // 8: rtc.Trickle.target:type_name -> rtc.Target
	5,  // 9: rtc.RTC.Signal:input_type -> rtc.Signalling
	5,  // 10: rtc.RTC.Signal:output_type -> rtc.Signalling
	10, // [10:11] is the sub-list for method output_type
	9,  // [9:10] is the sub-list for method input_type
	9,  // [9:9] is the sub-list for extension type_name
	9,  // [9:9] is the sub-list for extension extendee
	0,  // [0:9] is the sub-list for field type_name
}

func init() { file_protos_rtc_proto_init() }
func file_protos_rtc_proto_init() {
	if File_protos_rtc_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_protos_rtc_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Parameter); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protos_rtc_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*JoinRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protos_rtc_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*JoinReply); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protos_rtc_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Join); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protos_rtc_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Signalling); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protos_rtc_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Description); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protos_rtc_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Trickle); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protos_rtc_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Error); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_protos_rtc_proto_msgTypes[3].OneofWrappers = []interface{}{
		(*Join_Req)(nil),
		(*Join_Reply)(nil),
	}
	file_protos_rtc_proto_msgTypes[4].OneofWrappers = []interface{}{
		(*Signalling_Join)(nil),
		(*Signalling_Description)(nil),
		(*Signalling_Trickle)(nil),
		(*Signalling_Error)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_protos_rtc_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_protos_rtc_proto_goTypes,
		DependencyIndexes: file_protos_rtc_proto_depIdxs,
		EnumInfos:         file_protos_rtc_proto_enumTypes,
		MessageInfos:      file_protos_rtc_proto_msgTypes,
	}.Build()
	File_protos_rtc_proto = out.File
	file_protos_rtc_proto_rawDesc = nil
	file_protos_rtc_proto_goTypes = nil
	file_protos_rtc_proto_depIdxs = nil
}
