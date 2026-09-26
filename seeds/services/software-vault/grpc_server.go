package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

type vaultGRPCService interface {
	WrapKey(ctx context.Context, req *structpb.Struct) (*structpb.Struct, error)
	UnwrapKey(ctx context.Context, req *structpb.Struct) (*structpb.Struct, error)
	Sign(ctx context.Context, req *structpb.Struct) (*structpb.Struct, error)
	GenerateRandom(ctx context.Context, req *structpb.Struct) (*structpb.Struct, error)
	GetKeyInfo(ctx context.Context, req *structpb.Struct) (*structpb.Struct, error)
}

type vaultGRPCServer struct {
	svc *SoftwareVaultService
}

func registerVaultGRPCServer(server *grpc.Server, svc *SoftwareVaultService) {
	impl := &vaultGRPCServer{svc: svc}
	for _, serviceName := range []string{
		"vecta.hsm.v1.HsmConnectorService",
		"vecta.hsm.v1.HsmService",
		"vecta.software_vault.v1.SoftwareVaultService",
	} {
		server.RegisterService(&grpc.ServiceDesc{
			ServiceName: serviceName,
			HandlerType: (*vaultGRPCService)(nil),
			Methods: []grpc.MethodDesc{
				{MethodName: "WrapKey", Handler: wrapKeyGRPCHandler},
				{MethodName: "UnwrapKey", Handler: unwrapKeyGRPCHandler},
				{MethodName: "Sign", Handler: signGRPCHandler},
				{MethodName: "GenerateRandom", Handler: randomGRPCHandler},
				{MethodName: "GetKeyInfo", Handler: keyInfoGRPCHandler},
			},
			Streams:  []grpc.StreamDesc{},
			Metadata: "proto/hsm.proto",
		}, impl)
	}
}

func (s *vaultGRPCServer) WrapKey(ctx context.Context, in *structpb.Struct) (*structpb.Struct, error) {
	m := in.AsMap()
	plain, err := parseBytesField(m, "plaintext_dek_b64", "plaintext_dek", "plaintext_b64", "data_b64")
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	wrapped, iv, err := s.svc.WrapKey(ctx, plain)
	zeroizeAll(plain)
	if err != nil {
		return nil, grpcError(err)
	}
	out := map[string]interface{}{
		"wrapped_dek_b64":    b64(wrapped),
		"wrapped_dek_iv_b64": b64(iv),
		"provider":           s.svc.provider.Name(),
	}
	return structpb.NewStruct(out)
}

func (s *vaultGRPCServer) UnwrapKey(ctx context.Context, in *structpb.Struct) (*structpb.Struct, error) {
	m := in.AsMap()
	wrapped, err := parseBytesField(m, "wrapped_dek_b64", "wrapped_dek", "ciphertext_b64")
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	iv, err := parseBytesField(m, "wrapped_dek_iv_b64", "iv_b64", "iv")
	if err != nil {
		zeroizeAll(wrapped)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	plain, err := s.svc.UnwrapKey(ctx, wrapped, iv)
	zeroizeAll(wrapped, iv)
	if err != nil {
		return nil, grpcError(err)
	}
	out := map[string]interface{}{
		"plaintext_dek_b64": b64(plain),
	}
	zeroizeAll(plain)
	return structpb.NewStruct(out)
}

func (s *vaultGRPCServer) Sign(ctx context.Context, in *structpb.Struct) (*structpb.Struct, error) {
	m := in.AsMap()
	data, err := parseBytesField(m, "data_b64", "data", "payload_b64")
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	label := parseStringField(m, "key_label", "label")
	sig, err := s.svc.Sign(ctx, data, label)
	zeroizeAll(data)
	if err != nil {
		return nil, grpcError(err)
	}
	out := map[string]interface{}{
		"signature_b64": b64(sig),
		"algorithm":     "HMAC-SHA256",
		"key_label":     label,
		"provider":      s.svc.provider.Name(),
	}
	zeroizeAll(sig)
	return structpb.NewStruct(out)
}

func (s *vaultGRPCServer) GenerateRandom(ctx context.Context, in *structpb.Struct) (*structpb.Struct, error) {
	m := in.AsMap()
	length := parseIntField(m, "length", "size")
	rnd, err := s.svc.GenerateRandom(ctx, length)
	if err != nil {
		return nil, grpcError(err)
	}
	out := map[string]interface{}{
		"random_b64": b64(rnd),
		"length":     len(rnd),
		"provider":   s.svc.provider.Name(),
	}
	zeroizeAll(rnd)
	return structpb.NewStruct(out)
}

func (s *vaultGRPCServer) GetKeyInfo(ctx context.Context, in *structpb.Struct) (*structpb.Struct, error) {
	m := in.AsMap()
	label := parseStringField(m, "key_label", "label")
	info, err := s.svc.GetKeyInfo(ctx, label)
	if err != nil {
		return nil, grpcError(err)
	}
	body := map[string]interface{}{}
	for k, v := range info {
		body[k] = v
	}
	body["key_label"] = label
	return structpb.NewStruct(body)
}

func wrapKeyGRPCHandler(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	in := &structpb.Struct{}
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(vaultGRPCService).WrapKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: fullMethodName(ctx, "WrapKey")}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(vaultGRPCService).WrapKey(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, in, info, handler)
}

func unwrapKeyGRPCHandler(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	in := &structpb.Struct{}
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(vaultGRPCService).UnwrapKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: fullMethodName(ctx, "UnwrapKey")}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(vaultGRPCService).UnwrapKey(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, in, info, handler)
}

func signGRPCHandler(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	in := &structpb.Struct{}
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(vaultGRPCService).Sign(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: fullMethodName(ctx, "Sign")}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(vaultGRPCService).Sign(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, in, info, handler)
}

func randomGRPCHandler(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	in := &structpb.Struct{}
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(vaultGRPCService).GenerateRandom(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: fullMethodName(ctx, "GenerateRandom")}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(vaultGRPCService).GenerateRandom(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, in, info, handler)
}

func keyInfoGRPCHandler(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	in := &structpb.Struct{}
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(vaultGRPCService).GetKeyInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: fullMethodName(ctx, "GetKeyInfo")}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(vaultGRPCService).GetKeyInfo(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, in, info, handler)
}

func fullMethodName(ctx context.Context, method string) string {
	full, ok := grpc.Method(ctx)
	if ok && strings.TrimSpace(full) != "" {
		return full
	}
	return fmt.Sprintf("/vecta.hsm.v1.HsmConnectorService/%s", method)
}

func grpcError(err error) error {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		switch svcErr.HTTPStatus {
		case http.StatusBadRequest:
			return status.Error(codes.InvalidArgument, svcErr.Message)
		case http.StatusUnauthorized:
			return status.Error(codes.Unauthenticated, svcErr.Message)
		case http.StatusForbidden:
			return status.Error(codes.PermissionDenied, svcErr.Message)
		case http.StatusNotFound:
			return status.Error(codes.NotFound, svcErr.Message)
		case http.StatusServiceUnavailable:
			return status.Error(codes.Unavailable, svcErr.Message)
		default:
			return status.Error(codes.Internal, svcErr.Message)
		}
	}
	return status.Error(codes.Internal, err.Error())
}
