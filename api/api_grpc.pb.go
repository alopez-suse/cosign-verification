// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.21.12
// source: api/api.proto

package api

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

// SignatureVerificationClient is the client API for SignatureVerification service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type SignatureVerificationClient interface {
	ImageSignatures(ctx context.Context, in *ImageSignaturesRequest, opts ...grpc.CallOption) (*ImageSignaturesReply, error)
	ImageSigned(ctx context.Context, in *ImageSignedRequest, opts ...grpc.CallOption) (*ImageSignedReply, error)
}

type signatureVerificationClient struct {
	cc grpc.ClientConnInterface
}

func NewSignatureVerificationClient(cc grpc.ClientConnInterface) SignatureVerificationClient {
	return &signatureVerificationClient{cc}
}

func (c *signatureVerificationClient) ImageSignatures(ctx context.Context, in *ImageSignaturesRequest, opts ...grpc.CallOption) (*ImageSignaturesReply, error) {
	out := new(ImageSignaturesReply)
	err := c.cc.Invoke(ctx, "/api.SignatureVerification/ImageSignatures", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *signatureVerificationClient) ImageSigned(ctx context.Context, in *ImageSignedRequest, opts ...grpc.CallOption) (*ImageSignedReply, error) {
	out := new(ImageSignedReply)
	err := c.cc.Invoke(ctx, "/api.SignatureVerification/ImageSigned", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SignatureVerificationServer is the server API for SignatureVerification service.
// All implementations must embed UnimplementedSignatureVerificationServer
// for forward compatibility
type SignatureVerificationServer interface {
	ImageSignatures(context.Context, *ImageSignaturesRequest) (*ImageSignaturesReply, error)
	ImageSigned(context.Context, *ImageSignedRequest) (*ImageSignedReply, error)
	mustEmbedUnimplementedSignatureVerificationServer()
}

// UnimplementedSignatureVerificationServer must be embedded to have forward compatible implementations.
type UnimplementedSignatureVerificationServer struct {
}

func (UnimplementedSignatureVerificationServer) ImageSignatures(context.Context, *ImageSignaturesRequest) (*ImageSignaturesReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ImageSignatures not implemented")
}
func (UnimplementedSignatureVerificationServer) ImageSigned(context.Context, *ImageSignedRequest) (*ImageSignedReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ImageSigned not implemented")
}
func (UnimplementedSignatureVerificationServer) mustEmbedUnimplementedSignatureVerificationServer() {}

// UnsafeSignatureVerificationServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to SignatureVerificationServer will
// result in compilation errors.
type UnsafeSignatureVerificationServer interface {
	mustEmbedUnimplementedSignatureVerificationServer()
}

func RegisterSignatureVerificationServer(s grpc.ServiceRegistrar, srv SignatureVerificationServer) {
	s.RegisterService(&SignatureVerification_ServiceDesc, srv)
}

func _SignatureVerification_ImageSignatures_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ImageSignaturesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SignatureVerificationServer).ImageSignatures(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.SignatureVerification/ImageSignatures",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SignatureVerificationServer).ImageSignatures(ctx, req.(*ImageSignaturesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SignatureVerification_ImageSigned_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ImageSignedRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SignatureVerificationServer).ImageSigned(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.SignatureVerification/ImageSigned",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SignatureVerificationServer).ImageSigned(ctx, req.(*ImageSignedRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// SignatureVerification_ServiceDesc is the grpc.ServiceDesc for SignatureVerification service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var SignatureVerification_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "api.SignatureVerification",
	HandlerType: (*SignatureVerificationServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ImageSignatures",
			Handler:    _SignatureVerification_ImageSignatures_Handler,
		},
		{
			MethodName: "ImageSigned",
			Handler:    _SignatureVerification_ImageSigned_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/api.proto",
}