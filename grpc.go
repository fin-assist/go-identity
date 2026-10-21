package identity

import (
	"context"
	"errors"
	"strings"

	"github.com/fin-assist/contracts/gen/go/finerr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// AccessTable maps exact full gRPC methods to caller/model pairs. There are no
// wildcards or implicit exceptions: even GetSigningKeys needs its own entry.
type AccessTable map[string]map[string]Model

// ServiceChecker verifies service tokens. Its errors remain internal.
type ServiceChecker interface {
	VerifyService(context.Context, string) (string, error)
}

// UserChecker verifies access tokens. Its errors are normalized to INVALID_TOKEN.
type UserChecker interface {
	VerifyUser(context.Context, string) (string, error)
}

// Server checks identity for unary and streaming RPCs. It is concurrency safe
// when the injected checkers/observer are. Its access table is copied at creation.
type Server struct {
	table    AccessTable
	services ServiceChecker
	users    UserChecker
	observer Observer
}

// NewServer requires both checkers and a nonempty, valid table. An unknown method
// or caller is denied. Put these interceptors before tombstones and handlers.
func NewServer(table AccessTable, services ServiceChecker, users UserChecker, observer Observer) (*Server, error) {
	if len(table) == 0 || services == nil || users == nil {
		return nil, errors.New("identity: table and verifiers required")
	}
	copyTable := make(AccessTable, len(table))
	for method, callers := range table {
		if !strings.HasPrefix(method, "/") || strings.Count(method, "/") != 2 || len(callers) == 0 {
			return nil, errors.New("identity: invalid method rule")
		}
		copyTable[method] = make(map[string]Model, len(callers))
		for caller, model := range callers {
			if !serviceName(caller) || (model != User && model != System && model != NoUser) {
				return nil, errors.New("identity: invalid caller rule")
			}
			copyTable[method][caller] = model
		}
	}
	return &Server{copyTable, services, users, observer}, nil
}

func (s *Server) admit(ctx context.Context, method string) (context.Context, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	token, ok := bearer(md.Get("x-service-authorization"))
	if !ok {
		s.reject("invalid")
		return nil, internalStatus(codes.Unauthenticated)
	}
	caller, err := s.services.VerifyService(ctx, token)
	if err != nil || !serviceName(caller) {
		return nil, internalStatus(codes.Unauthenticated)
	}
	model, ok := s.table[method][caller]
	if !ok {
		s.reject("forbidden")
		return nil, internalStatus(codes.PermissionDenied)
	}
	p := principal{caller: caller, model: model}
	if model == User {
		p.token, ok = bearer(md.Get("authorization"))
		if !ok {
			s.reject("invalid")
			return nil, finerr.InvalidToken()
		}
		p.userID, err = s.users.VerifyUser(ctx, p.token)
		if err != nil || strings.TrimSpace(p.userID) == "" {
			return nil, finerr.InvalidToken()
		}
	}
	return context.WithValue(ctx, identityKey{}, p), nil
}

func (s *Server) reject(reason string) {
	if s.observer != nil {
		s.observer.Reject("access", reason)
	}
}

// internalStatus is deliberately bare: internal authentication/authorization
// failures carry neither ErrorInfo nor caller/token details (grpc-api.md 5.1).
func internalStatus(code codes.Code) error {
	return status.Error(code, "") //nolint:forbidigo // Internal refusal, not a client-facing registry error.
}

func (s *Server) request(ctx context.Context, req any) error {
	p, _ := ctx.Value(identityKey{}).(principal)
	if p.model != User {
		return nil
	}
	m, ok := req.(proto.Message)
	if !ok {
		return nil
	}
	r := m.ProtoReflect()
	field := r.Descriptor().Fields().ByName("user_id")
	if field != nil {
		// Contract user_id is a string; a different schema cannot be admitted safely.
		if field.Kind() != protoreflect.StringKind || field.IsList() || field.IsMap() {
			s.reject("user_id")
			return internalStatus(codes.PermissionDenied)
		}
		id := r.Get(field).String()
		if id != "" && id != p.userID {
			s.reject("user_id")
			return internalStatus(codes.PermissionDenied)
		}
	}
	return nil
}

// Unary checks service and user identity and rejects a foreign request user_id.
func (s *Server) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		ctx, err := s.admit(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		if err = s.request(ctx, req); err != nil {
			return nil, err
		}
		return next(ctx, req)
	}
}

type identityStream struct {
	grpc.ServerStream
	ctx    context.Context
	server *Server
}

func (s *identityStream) Context() context.Context { return s.ctx }
func (s *identityStream) RecvMsg(m any) error {
	if err := s.ServerStream.RecvMsg(m); err != nil {
		return err
	}
	return s.server.request(s.ctx, m)
}

// Stream authenticates at stream admission, not on each message: a long stream
// may outlive its access token. Each received user_id still has to match sub.
func (s *Server) Stream() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, next grpc.StreamHandler) error {
		ctx, err := s.admit(stream.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		return next(srv, &identityStream{stream, ctx, s})
	}
}

func outgoing(ctx context.Context, source TokenSource) (context.Context, error) {
	if source == nil {
		return nil, errors.New("identity: service token source required")
	}
	token, err := source.Token(ctx)
	if err != nil {
		return nil, errors.New("identity: service token unavailable")
	}
	if _, ok := bearer([]string{"Bearer " + token}); !ok {
		return nil, errors.New("identity: invalid service token")
	}
	md, _ := metadata.FromOutgoingContext(ctx)
	md = md.Copy()
	md.Set("x-service-authorization", "Bearer "+token)
	md.Delete("authorization")
	if p, ok := ctx.Value(identityKey{}).(principal); ok && p.model == User {
		md.Set("authorization", "Bearer "+p.token)
	}
	return metadata.NewOutgoingContext(ctx, md), nil
}

// UnaryClient adds the current service token and forwards only an access token
// verified by this package, preserving its original bytes. Existing auth metadata
// is replaced; unrelated outgoing metadata is retained.
func UnaryClient(source TokenSource) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, next grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx, err := outgoing(ctx, source)
		if err != nil {
			return err
		}
		return next(ctx, method, req, reply, cc, opts...)
	}
}

// StreamClient adds identity when opening a stream, with the same rules as UnaryClient.
func StreamClient(source TokenSource) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, next grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		ctx, err := outgoing(ctx, source)
		if err != nil {
			return nil, err
		}
		return next(ctx, desc, cc, method, opts...)
	}
}

// MaskMetadata returns an independent redacted copy for logging. Tokens,
// authorization and idempotency keys are never included in its values.
func MaskMetadata(md metadata.MD) metadata.MD {
	copyMD := md.Copy()
	for key := range copyMD {
		lower := strings.ToLower(key)
		if lower == "authorization" || lower == "x-service-authorization" || lower == "idempotency-key" || strings.Contains(lower, "token") {
			copyMD[key] = []string{"[REDACTED]"}
		}
	}
	return copyMD
}
