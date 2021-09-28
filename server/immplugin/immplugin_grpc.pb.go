// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package immplugin

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// ImmPluginClient is the client API for ImmPlugin service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ImmPluginClient interface {
	DoPlugin(ctx context.Context, in *DoPluginRequest, opts ...grpc.CallOption) (*DoPluginReply, error)
}

type immPluginClient struct {
	cc grpc.ClientConnInterface
}

func NewImmPluginClient(cc grpc.ClientConnInterface) ImmPluginClient {
	return &immPluginClient{cc}
}

func (c *immPluginClient) DoPlugin(ctx context.Context, in *DoPluginRequest, opts ...grpc.CallOption) (*DoPluginReply, error) {
	out := new(DoPluginReply)
	err := c.cc.Invoke(ctx, "/immplugin.ImmPlugin/DoPlugin", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ImmPluginServer is the server API for ImmPlugin service.
// All implementations should embed UnimplementedImmPluginServer
// for forward compatibility
type ImmPluginServer interface {
	DoPlugin(context.Context, *DoPluginRequest) (*DoPluginReply, error)
}

// UnimplementedImmPluginServer should be embedded to have forward compatible implementations.
type UnimplementedImmPluginServer struct {
}

func (*UnimplementedImmPluginServer) DoPlugin(context.Context, *DoPluginRequest) (*DoPluginReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DoPlugin not implemented")
}

func RegisterImmPluginServer(s *grpc.Server, srv ImmPluginServer) {
	s.RegisterService(&_ImmPlugin_serviceDesc, srv)
}

func _ImmPlugin_DoPlugin_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DoPluginRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ImmPluginServer).DoPlugin(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/immplugin.ImmPlugin/DoPlugin",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ImmPluginServer).DoPlugin(ctx, req.(*DoPluginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _ImmPlugin_serviceDesc = grpc.ServiceDesc{
	ServiceName: "immplugin.ImmPlugin",
	HandlerType: (*ImmPluginServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "DoPlugin",
			Handler:    _ImmPlugin_DoPlugin_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/immplugin.proto",
}
