package identity

import (
	"context"
	"errors"
	"io"
	"testing"

	analyticsv1 "github.com/fin-assist/contracts/gen/go/finassist/analytics/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
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
func TestStreamChecksEveryMessage(t *testing.T) {
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
