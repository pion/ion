// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        v3.12.4
// source: protos/islb.proto

package islb

import (
	proto "github.com/golang/protobuf/proto"
	ion "github.com/pion/ion/pkg/grpc/ion"
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

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type FindNodeRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Sid     string `protobuf:"bytes,1,opt,name=sid,proto3" json:"sid,omitempty"`
	Nid     string `protobuf:"bytes,2,opt,name=nid,proto3" json:"nid,omitempty"`
	Service string `protobuf:"bytes,3,opt,name=service,proto3" json:"service,omitempty"`
}

func (x *FindNodeRequest) Reset() {
	*x = FindNodeRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protos_islb_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FindNodeRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FindNodeRequest) ProtoMessage() {}

func (x *FindNodeRequest) ProtoReflect() protoreflect.Message {
	mi := &file_protos_islb_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FindNodeRequest.ProtoReflect.Descriptor instead.
func (*FindNodeRequest) Descriptor() ([]byte, []int) {
	return file_protos_islb_proto_rawDescGZIP(), []int{0}
}

func (x *FindNodeRequest) GetSid() string {
	if x != nil {
		return x.Sid
	}
	return ""
}

func (x *FindNodeRequest) GetNid() string {
	if x != nil {
		return x.Nid
	}
	return ""
}

func (x *FindNodeRequest) GetService() string {
	if x != nil {
		return x.Service
	}
	return ""
}

type FindNodeReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Nodes []*ion.Node `protobuf:"bytes,1,rep,name=nodes,proto3" json:"nodes,omitempty"`
}

func (x *FindNodeReply) Reset() {
	*x = FindNodeReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protos_islb_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FindNodeReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FindNodeReply) ProtoMessage() {}

func (x *FindNodeReply) ProtoReflect() protoreflect.Message {
	mi := &file_protos_islb_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FindNodeReply.ProtoReflect.Descriptor instead.
func (*FindNodeReply) Descriptor() ([]byte, []int) {
	return file_protos_islb_proto_rawDescGZIP(), []int{1}
}

func (x *FindNodeReply) GetNodes() []*ion.Node {
	if x != nil {
		return x.Nodes
	}
	return nil
}

type ISLBEvent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Payload:
	//	*ISLBEvent_PeerEvent
	//	*ISLBEvent_StreamEvent
	//	*ISLBEvent_Msg
	Payload isISLBEvent_Payload `protobuf_oneof:"payload"`
}

func (x *ISLBEvent) Reset() {
	*x = ISLBEvent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protos_islb_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ISLBEvent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ISLBEvent) ProtoMessage() {}

func (x *ISLBEvent) ProtoReflect() protoreflect.Message {
	mi := &file_protos_islb_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ISLBEvent.ProtoReflect.Descriptor instead.
func (*ISLBEvent) Descriptor() ([]byte, []int) {
	return file_protos_islb_proto_rawDescGZIP(), []int{2}
}

func (m *ISLBEvent) GetPayload() isISLBEvent_Payload {
	if m != nil {
		return m.Payload
	}
	return nil
}

func (x *ISLBEvent) GetPeerEvent() *ion.PeerEvent {
	if x, ok := x.GetPayload().(*ISLBEvent_PeerEvent); ok {
		return x.PeerEvent
	}
	return nil
}

func (x *ISLBEvent) GetStreamEvent() *ion.StreamEvent {
	if x, ok := x.GetPayload().(*ISLBEvent_StreamEvent); ok {
		return x.StreamEvent
	}
	return nil
}

func (x *ISLBEvent) GetMsg() *ion.Message {
	if x, ok := x.GetPayload().(*ISLBEvent_Msg); ok {
		return x.Msg
	}
	return nil
}

type isISLBEvent_Payload interface {
	isISLBEvent_Payload()
}

type ISLBEvent_PeerEvent struct {
	PeerEvent *ion.PeerEvent `protobuf:"bytes,2,opt,name=peerEvent,proto3,oneof"`
}

type ISLBEvent_StreamEvent struct {
	StreamEvent *ion.StreamEvent `protobuf:"bytes,3,opt,name=streamEvent,proto3,oneof"`
}

type ISLBEvent_Msg struct {
	Msg *ion.Message `protobuf:"bytes,4,opt,name=msg,proto3,oneof"`
}

func (*ISLBEvent_PeerEvent) isISLBEvent_Payload() {}

func (*ISLBEvent_StreamEvent) isISLBEvent_Payload() {}

func (*ISLBEvent_Msg) isISLBEvent_Payload() {}

var File_protos_islb_proto protoreflect.FileDescriptor

var file_protos_islb_proto_rawDesc = []byte{
	0x0a, 0x11, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2f, 0x69, 0x73, 0x6c, 0x62, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x04, 0x69, 0x73, 0x6c, 0x62, 0x1a, 0x10, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x73, 0x2f, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x4f, 0x0a, 0x0f, 0x46,
	0x69, 0x6e, 0x64, 0x4e, 0x6f, 0x64, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x10,
	0x0a, 0x03, 0x73, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x73, 0x69, 0x64,
	0x12, 0x10, 0x0a, 0x03, 0x6e, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6e,
	0x69, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x22, 0x30, 0x0a, 0x0d,
	0x46, 0x69, 0x6e, 0x64, 0x4e, 0x6f, 0x64, 0x65, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x12, 0x1f, 0x0a,
	0x05, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x09, 0x2e, 0x69,
	0x6f, 0x6e, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x52, 0x05, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x22, 0x9e,
	0x01, 0x0a, 0x09, 0x49, 0x53, 0x4c, 0x42, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x12, 0x2e, 0x0a, 0x09,
	0x70, 0x65, 0x65, 0x72, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x0e, 0x2e, 0x69, 0x6f, 0x6e, 0x2e, 0x50, 0x65, 0x65, 0x72, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x48,
	0x00, 0x52, 0x09, 0x70, 0x65, 0x65, 0x72, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x12, 0x34, 0x0a, 0x0b,
	0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x10, 0x2e, 0x69, 0x6f, 0x6e, 0x2e, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x45, 0x76,
	0x65, 0x6e, 0x74, 0x48, 0x00, 0x52, 0x0b, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x45, 0x76, 0x65,
	0x6e, 0x74, 0x12, 0x20, 0x0a, 0x03, 0x6d, 0x73, 0x67, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x0c, 0x2e, 0x69, 0x6f, 0x6e, 0x2e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x48, 0x00, 0x52,
	0x03, 0x6d, 0x73, 0x67, 0x42, 0x09, 0x0a, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x32,
	0x9c, 0x01, 0x0a, 0x04, 0x49, 0x53, 0x4c, 0x42, 0x12, 0x38, 0x0a, 0x08, 0x46, 0x69, 0x6e, 0x64,
	0x4e, 0x6f, 0x64, 0x65, 0x12, 0x15, 0x2e, 0x69, 0x73, 0x6c, 0x62, 0x2e, 0x46, 0x69, 0x6e, 0x64,
	0x4e, 0x6f, 0x64, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x13, 0x2e, 0x69, 0x73,
	0x6c, 0x62, 0x2e, 0x46, 0x69, 0x6e, 0x64, 0x4e, 0x6f, 0x64, 0x65, 0x52, 0x65, 0x70, 0x6c, 0x79,
	0x22, 0x00, 0x12, 0x2a, 0x0a, 0x09, 0x50, 0x6f, 0x73, 0x74, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x12,
	0x0f, 0x2e, 0x69, 0x73, 0x6c, 0x62, 0x2e, 0x49, 0x53, 0x4c, 0x42, 0x45, 0x76, 0x65, 0x6e, 0x74,
	0x1a, 0x0a, 0x2e, 0x69, 0x6f, 0x6e, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x22, 0x00, 0x12, 0x2e,
	0x0a, 0x0b, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x12, 0x0a, 0x2e,
	0x69, 0x6f, 0x6e, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x0f, 0x2e, 0x69, 0x73, 0x6c, 0x62,
	0x2e, 0x49, 0x53, 0x4c, 0x42, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x22, 0x00, 0x30, 0x01, 0x42, 0x23,
	0x5a, 0x21, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x69, 0x6f,
	0x6e, 0x2f, 0x69, 0x6f, 0x6e, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x69,
	0x73, 0x6c, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_protos_islb_proto_rawDescOnce sync.Once
	file_protos_islb_proto_rawDescData = file_protos_islb_proto_rawDesc
)

func file_protos_islb_proto_rawDescGZIP() []byte {
	file_protos_islb_proto_rawDescOnce.Do(func() {
		file_protos_islb_proto_rawDescData = protoimpl.X.CompressGZIP(file_protos_islb_proto_rawDescData)
	})
	return file_protos_islb_proto_rawDescData
}

var file_protos_islb_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_protos_islb_proto_goTypes = []interface{}{
	(*FindNodeRequest)(nil), // 0: islb.FindNodeRequest
	(*FindNodeReply)(nil),   // 1: islb.FindNodeReply
	(*ISLBEvent)(nil),       // 2: islb.ISLBEvent
	(*ion.Node)(nil),        // 3: ion.Node
	(*ion.PeerEvent)(nil),   // 4: ion.PeerEvent
	(*ion.StreamEvent)(nil), // 5: ion.StreamEvent
	(*ion.Message)(nil),     // 6: ion.Message
	(*ion.Empty)(nil),       // 7: ion.Empty
}
var file_protos_islb_proto_depIdxs = []int32{
	3, // 0: islb.FindNodeReply.nodes:type_name -> ion.Node
	4, // 1: islb.ISLBEvent.peerEvent:type_name -> ion.PeerEvent
	5, // 2: islb.ISLBEvent.streamEvent:type_name -> ion.StreamEvent
	6, // 3: islb.ISLBEvent.msg:type_name -> ion.Message
	0, // 4: islb.ISLB.FindNode:input_type -> islb.FindNodeRequest
	2, // 5: islb.ISLB.PostEvent:input_type -> islb.ISLBEvent
	7, // 6: islb.ISLB.HandleEvent:input_type -> ion.Empty
	1, // 7: islb.ISLB.FindNode:output_type -> islb.FindNodeReply
	7, // 8: islb.ISLB.PostEvent:output_type -> ion.Empty
	2, // 9: islb.ISLB.HandleEvent:output_type -> islb.ISLBEvent
	7, // [7:10] is the sub-list for method output_type
	4, // [4:7] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_protos_islb_proto_init() }
func file_protos_islb_proto_init() {
	if File_protos_islb_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_protos_islb_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FindNodeRequest); i {
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
		file_protos_islb_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FindNodeReply); i {
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
		file_protos_islb_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ISLBEvent); i {
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
	file_protos_islb_proto_msgTypes[2].OneofWrappers = []interface{}{
		(*ISLBEvent_PeerEvent)(nil),
		(*ISLBEvent_StreamEvent)(nil),
		(*ISLBEvent_Msg)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_protos_islb_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_protos_islb_proto_goTypes,
		DependencyIndexes: file_protos_islb_proto_depIdxs,
		MessageInfos:      file_protos_islb_proto_msgTypes,
	}.Build()
	File_protos_islb_proto = out.File
	file_protos_islb_proto_rawDesc = nil
	file_protos_islb_proto_goTypes = nil
	file_protos_islb_proto_depIdxs = nil
}
