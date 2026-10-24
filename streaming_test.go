package identity

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	analyticsv1 "github.com/fin-assist/contracts/gen/go/finassist/analytics/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

type testStream struct {
	grpc.ServerStream
	ctx   context.Context
	field string
	err   error
}

func (s *testStream) Context() context.Context { return s.ctx }
func (s *testStream) RecvMsg(m any) error {
	if s.err != nil {
		return s.err
	}
	r := m.(*analyticsv1.GetAnalyticsRequest)
	r.UserId = proto.String(s.field)
	return nil
}
func TestUnitStreamChecksEveryMessage(t *testing.T) {
	s := serverForTest(t)
	for _, field := range []string{"", "u", "victim"} {
		stream := &testStream{ctx: incoming("bank-bff", "access"), field: field}
		e := s.Stream()(nil, stream, &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}, func(_ any, stream grpc.ServerStream) error {
			if id, ok := UserID(stream.Context()); !ok || id != "u" {
				t.Fatal("stream context missing")
			}
			return stream.RecvMsg(&analyticsv1.GetAnalyticsRequest{})
		})
		if (field == "victim") != (status.Code(e) == codes.PermissionDenied) {
			t.Fatal(field, e)
		}
	}
	called := false
	e := s.Stream()(nil, &testStream{ctx: incoming("foreign", "")}, &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}, func(any, grpc.ServerStream) error { called = true; return nil })
	if called || status.Code(e) != codes.PermissionDenied {
		t.Fatal("foreign stream admitted", e)
	}
	stream := &identityStream{ServerStream: &testStream{err: io.EOF}, server: s}
	if e := stream.RecvMsg(nil); !errors.Is(e, io.EOF) {
		t.Fatal(e)
	}
	userCtx, e := s.admit(incoming("bank-bff", "access"), "/test.Service/Method")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = SystemUserID(userCtx, "victim"); e == nil {
		t.Fatal("user promoted to system")
	}
}

func TestUnitRequestSchemaGuard(t *testing.T) {
	s := serverForTest(t)
	ctx, e := s.admit(incoming("bank-bff", "access"), "/test.Service/Method")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.request(ctx, struct{}{}); e != nil {
		t.Fatal(e)
	}
	descriptor, e := protodesc.NewFile(&descriptorpb.FileDescriptorProto{Name: proto.String("test.proto"), Syntax: proto.String("proto3"), MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Request"), Field: []*descriptorpb.FieldDescriptorProto{{Name: proto.String("user_id"), Number: proto.Int32(1), Type: descriptorpb.FieldDescriptorProto_TYPE_INT64.Enum()}}}}}, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.request(ctx, dynamicpb.NewMessage(descriptor.Messages().Get(0))); status.Code(e) != codes.PermissionDenied {
		t.Fatal("invalid user_id schema admitted", e)
	}
}

type messageStream interface{ Exchange(grpc.ServerStream) error }
type messageStreamAPI struct{ processed atomic.Int32 }

func (s *messageStreamAPI) Exchange(stream grpc.ServerStream) error {
	for {
		request := new(analyticsv1.GetAnalyticsRequest)
		if e := stream.RecvMsg(request); e != nil {
			if errors.Is(e, io.EOF) {
				return nil
			}
			return e
		}
		s.processed.Add(1)
		if e := stream.SendMsg(&analyticsv1.GetAnalyticsResponse{}); e != nil {
			return e
		}
	}
}

func TestIntegrationUserStreamRejectsSecondForeignMessage(t *testing.T) {
	const method = "/test.Identity/Exchange"
	auth, e := NewServer(AccessTable{method: {"bank-bff": User}}, goodService(), goodUser(), nil)
	if e != nil {
		t.Fatal(e)
	}
	descriptor := grpc.ServiceDesc{ServiceName: "test.Identity", HandlerType: (*messageStream)(nil), Streams: []grpc.StreamDesc{{StreamName: "Exchange", ServerStreams: true, ClientStreams: true, Handler: func(srv any, stream grpc.ServerStream) error { return srv.(messageStream).Exchange(stream) }}}}
	api := new(messageStreamAPI)
	server := grpc.NewServer(grpc.ChainStreamInterceptor(auth.Stream()))
	server.RegisterService(&descriptor, api)
	conn := dialServer(t, server, tokenFunc(func(context.Context) (string, error) { return "bank-bff", nil }))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, identityKey{}, principal{model: User, userID: "u", token: "access"})
	stream, e := conn.NewStream(ctx, &descriptor.Streams[0], method)
	if e != nil {
		t.Fatal(e)
	}
	if e = stream.SendMsg(&analyticsv1.GetAnalyticsRequest{UserId: proto.String("u")}); e != nil {
		t.Fatal(e)
	}
	if e = stream.RecvMsg(&analyticsv1.GetAnalyticsResponse{}); e != nil {
		t.Fatal("first message rejected", e)
	}
	if api.processed.Load() != 1 {
		t.Fatal("first message not processed")
	}
	// The first response is the barrier: the same admitted stream now sends a
	// different user. A first-message-only check would process it and send a reply.
	if e = stream.SendMsg(&analyticsv1.GetAnalyticsRequest{UserId: proto.String("victim")}); e != nil {
		t.Fatal(e)
	}
	e = stream.RecvMsg(&analyticsv1.GetAnalyticsResponse{})
	if status.Code(e) != codes.PermissionDenied || len(status.Convert(e).Details()) != 0 {
		t.Fatal("foreign second message admitted or details leaked", e)
	}
	if api.processed.Load() != 1 {
		t.Fatal("foreign second message reached processing")
	}
}
