// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package sfu

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// SFUClient is the client API for SFU service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type SFUClient interface {
	Signal(ctx context.Context, opts ...grpc.CallOption) (SFU_SignalClient, error)
}

type sFUClient struct {
	cc grpc.ClientConnInterface
}

func NewSFUClient(cc grpc.ClientConnInterface) SFUClient {
	return &sFUClient{cc}
}

func (c *sFUClient) Signal(ctx context.Context, opts ...grpc.CallOption) (SFU_SignalClient, error) {
	stream, err := c.cc.NewStream(ctx, &SFU_ServiceDesc.Streams[0], "/sfu.SFU/Signal", opts...)
	if err != nil {
		return nil, err
	}
	x := &sFUSignalClient{stream}
	return x, nil
}

type SFU_SignalClient interface {
	Send(*SignalRequest) error
	Recv() (*SignalReply, error)
	grpc.ClientStream
}

type sFUSignalClient struct {
	grpc.ClientStream
}

func (x *sFUSignalClient) Send(m *SignalRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *sFUSignalClient) Recv() (*SignalReply, error) {
	m := new(SignalReply)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// SFUServer is the server API for SFU service.
// All implementations must embed UnimplementedSFUServer
// for forward compatibility
type SFUServer interface {
	Signal(SFU_SignalServer) error
	mustEmbedUnimplementedSFUServer()
}

// UnimplementedSFUServer must be embedded to have forward compatible implementations.
type UnimplementedSFUServer struct {
}

func (UnimplementedSFUServer) Signal(SFU_SignalServer) error {
	return status.Errorf(codes.Unimplemented, "method Signal not implemented")
}
func (UnimplementedSFUServer) mustEmbedUnimplementedSFUServer() {}

// UnsafeSFUServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to SFUServer will
// result in compilation errors.
type UnsafeSFUServer interface {
	mustEmbedUnimplementedSFUServer()
}

func RegisterSFUServer(s grpc.ServiceRegistrar, srv SFUServer) {
	s.RegisterService(&SFU_ServiceDesc, srv)
}

func _SFU_Signal_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(SFUServer).Signal(&sFUSignalServer{stream})
}

type SFU_SignalServer interface {
	Send(*SignalReply) error
	Recv() (*SignalRequest, error)
	grpc.ServerStream
}

type sFUSignalServer struct {
	grpc.ServerStream
}

func (x *sFUSignalServer) Send(m *SignalReply) error {
	return x.ServerStream.SendMsg(m)
}

func (x *sFUSignalServer) Recv() (*SignalRequest, error) {
	m := new(SignalRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// SFU_ServiceDesc is the grpc.ServiceDesc for SFU service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var SFU_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "sfu.SFU",
	HandlerType: (*SFUServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Signal",
			Handler:       _SFU_Signal_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "protos/sfu.proto",
}
