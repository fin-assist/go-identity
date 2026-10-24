package identity

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	analyticsv1 "github.com/fin-assist/contracts/gen/go/finassist/analytics/v1"
	userv1 "github.com/fin-assist/contracts/gen/go/finassist/user/v1"
	"github.com/fin-assist/contracts/gen/go/finerr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

type serviceFunc func(context.Context, string) (string, error)

func (f serviceFunc) VerifyService(c context.Context, t string) (string, error) { return f(c, t) }

type userFunc func(context.Context, string) (string, error)

func (f userFunc) VerifyUser(c context.Context, t string) (string, error) { return f(c, t) }

type tokenFunc func(context.Context) (string, error)

func (f tokenFunc) Token(c context.Context) (string, error) { return f(c) }
func goodService() ServiceChecker {
	return serviceFunc(func(_ context.Context, s string) (string, error) {
		if s == "bad" {
			return "", errors.New("secret")
		}
		return s, nil
	})
}
func goodUser() UserChecker {
	return userFunc(func(_ context.Context, s string) (string, error) {
		if s != "access" {
			return "", errors.New("secret")
		}
		return "u", nil
	})
}
func serverForTest(t *testing.T) *Server {
	t.Helper()
	s, e := NewServer(AccessTable{"/test.Service/Method": {"bank-bff": User, "assistant": System, "user": NoUser}}, goodService(), goodUser(), &observer{})
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func incoming(service, user string) context.Context {
	md := metadata.MD{}
	if service != "" {
		md.Set("x-service-authorization", "Bearer "+service)
	}
	if user != "" {
		md.Set("authorization", "Bearer "+user)
	}
	return metadata.NewIncomingContext(context.Background(), md)
}
func TestUnitServerAdmission(t *testing.T) {
	s := serverForTest(t)
	for _, tc := range []struct {
		name, service, user, method, field string
		code                               codes.Code
		reason                             string
	}{{"user", "bank-bff", "access", "/test.Service/Method", "", codes.OK, ""}, {"same user", "bank-bff", "access", "/test.Service/Method", "u", codes.OK, ""}, {"foreign user", "bank-bff", "access", "/test.Service/Method", "victim", codes.PermissionDenied, ""}, {"system", "assistant", "", "/test.Service/Method", "victim", codes.OK, ""}, {"no user", "user", "", "/test.Service/Method", "", codes.OK, ""}, {"missing service", "", "", "/test.Service/Method", "", codes.Unauthenticated, ""}, {"invalid service", "bad", "access", "/test.Service/Method", "", codes.Unauthenticated, ""}, {"foreign caller", "foreign", "access", "/test.Service/Method", "", codes.PermissionDenied, ""}, {"missing method", "bank-bff", "access", "/test.Service/New", "", codes.PermissionDenied, ""}, {"missing user", "bank-bff", "", "/test.Service/Method", "", codes.Unauthenticated, "INVALID_TOKEN"}, {"bad user", "bank-bff", "bad", "/test.Service/Method", "", codes.Unauthenticated, "INVALID_TOKEN"}} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			req := &analyticsv1.GetAnalyticsRequest{}
			if tc.field != "" {
				req.UserId = proto.String(tc.field)
			}
			_, e := s.Unary()(incoming(tc.service, tc.user), req, &grpc.UnaryServerInfo{FullMethod: tc.method}, func(ctx context.Context, _ any) (any, error) {
				called = true
				if c, ok := Caller(ctx); !ok || c != tc.service {
					t.Fatal("caller missing")
				}
				if tc.service == "bank-bff" {
					if id, ok := UserID(ctx); !ok || id != "u" {
						t.Fatal("user missing")
					}
				}
				return nil, nil
			})
			if status.Code(e) != tc.code || called != (tc.code == codes.OK) {
				t.Fatalf("called=%v err=%v", called, e)
			}
			if tc.reason != "" {
				rest, ok := finerr.ToREST(e)
				if !ok || rest.Code != tc.reason {
					t.Fatal("wrong reason", e)
				}
			} else if e != nil && len(status.Convert(e).Details()) != 0 {
				t.Fatal("internal details leaked")
			}
		})
	}
	ctx, e := s.admit(incoming("assistant", "access"), "/test.Service/Method")
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := UserID(ctx); ok {
		t.Fatal("system acquired user identity")
	}
	if id, e := SystemUserID(ctx, "victim"); e != nil || id != "victim" {
		t.Fatal(id, e)
	}
	if _, e = SystemUserID(ctx, ""); e == nil {
		t.Fatal("empty system field")
	}
	if _, e = SystemUserID(context.Background(), "victim"); e == nil {
		t.Fatal("unauthenticated system user")
	}
	md := metadata.Pairs("x-service-authorization", "Bearer bank-bff", "x-service-authorization", "Bearer assistant")
	if _, e = s.admit(metadata.NewIncomingContext(context.Background(), md), "/test.Service/Method"); e == nil {
		t.Fatal("ambiguous credentials")
	}
	for _, table := range []AccessTable{nil, {"bad": {"bank-bff": User}}, {"/s/m": {}}, {"/s/m": {"BAD": User}}, {"/s/m": {"bank-bff": Model(99)}}} {
		if _, e := NewServer(table, goodService(), goodUser(), nil); e == nil {
			t.Fatal("invalid table accepted")
		}
	}
	table := AccessTable{"/s/m": {"bank-bff": User}}
	copyServer, _ := NewServer(table, goodService(), goodUser(), nil)
	table["/s/m"]["bank-bff"] = NoUser
	if _, e := copyServer.admit(incoming("bank-bff", ""), "/s/m"); e == nil {
		t.Fatal("table not copied")
	}
}

func TestUnitClientsAndMasking(t *testing.T) {
	src := tokenFunc(func(context.Context) (string, error) { return "svc", nil })
	ctx := context.WithValue(context.Background(), identityKey{}, principal{model: User, userID: "u", token: "exact.token"})
	md := metadata.Pairs("authorization", "Bearer forged", "x-service-authorization", "forged", "x-request-id", "r")
	ctx = metadata.NewOutgoingContext(ctx, md)
	invoke := func(c context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		out, _ := metadata.FromOutgoingContext(c)
		if out.Get("authorization")[0] != "Bearer exact.token" || out.Get("x-service-authorization")[0] != "Bearer svc" || out.Get("x-request-id")[0] != "r" {
			t.Fatal(out)
		}
		return nil
	}
	if e := UnaryClient(src)(ctx, "m", nil, nil, nil, invoke); e != nil {
		t.Fatal(e)
	}
	if _, e := StreamClient(src)(ctx, nil, nil, "m", func(c context.Context, _ *grpc.StreamDesc, _ *grpc.ClientConn, _ string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
		return nil, invoke(c, "m", nil, nil, nil)
	}); e != nil {
		t.Fatal(e)
	}
	if md.Get("authorization")[0] != "Bearer forged" {
		t.Fatal("metadata mutated")
	}
	out, e := outgoing(metadata.NewOutgoingContext(context.Background(), md), src)
	if e != nil {
		t.Fatal(e)
	}
	clean, _ := metadata.FromOutgoingContext(out)
	if len(clean.Get("authorization")) != 0 {
		t.Fatal("unverified token forwarded")
	}
	for _, bad := range []TokenSource{nil, tokenFunc(func(context.Context) (string, error) { return "", errors.New("secret") }), tokenFunc(func(context.Context) (string, error) { return "a\nb", nil })} {
		if e := UnaryClient(bad)(ctx, "", nil, nil, nil, func(context.Context, string, any, any, *grpc.ClientConn, ...grpc.CallOption) error {
			t.Fatal("invoked after failure")
			return nil
		}); e == nil || strings.Contains(e.Error(), "secret") {
			t.Fatal(e)
		}
		if _, e := StreamClient(bad)(ctx, nil, nil, "", nil); e == nil {
			t.Fatal("stream source error ignored")
		}
	}
	sensitive := metadata.Pairs("authorization", "secret", "x-service-authorization", "secret", "idempotency-key", "secret", "registration_token", "secret", "x-request-id", "r")
	masked := MaskMetadata(sensitive)
	for key, values := range masked {
		if key != "x-request-id" && values[0] != "[REDACTED]" {
			t.Fatal(masked)
		}
	}
	if sensitive.Get("authorization")[0] != "secret" {
		t.Fatal("source mutated")
	}
	for _, v := range [][]string{nil, {"Bearer x", "Bearer y"}, {"Basic x"}, {"Bearer "}, {"Bearer x y"}, {strings.Repeat("x", maxToken+8)}} {
		if _, ok := bearer(v); ok {
			t.Fatal(v)
		}
	}
}

type analyticsAPI struct {
	analyticsv1.UnimplementedAnalyticsServiceServer
	calls atomic.Int32
	t     *testing.T
}

func (a *analyticsAPI) GetAnalytics(ctx context.Context, r *analyticsv1.GetAnalyticsRequest) (*analyticsv1.GetAnalyticsResponse, error) {
	a.calls.Add(1)
	c, ok := Caller(ctx)
	if !ok {
		a.t.Fatal("missing caller")
	}
	if c == "bank-bff" {
		if id, ok := UserID(ctx); !ok || id != "user-1" {
			a.t.Fatal("missing user")
		}
	} else {
		if _, e := SystemUserID(ctx, r.GetUserId()); e != nil {
			return nil, e
		}
	}
	_ = grpc.SetHeader(ctx, metadata.Pairs("x-request-id", "server-r"))
	return &analyticsv1.GetAnalyticsResponse{}, nil
}

type keysAPI struct {
	userv1.UnimplementedUserInternalServiceServer
	body string
}

func (k *keysAPI) GetSigningKeys(context.Context, *userv1.GetSigningKeysRequest) (*userv1.GetSigningKeysResponse, error) {
	return &userv1.GetSigningKeysResponse{JwksJson: k.body}, nil
}

type healthAPI struct {
	grpc_health_v1.UnimplementedHealthServer
}

func (healthAPI) Watch(_ *grpc_health_v1.HealthCheckRequest, s grpc.ServerStreamingServer[grpc_health_v1.HealthCheckResponse]) error {
	if _, ok := Caller(s.Context()); !ok {
		return errors.New("missing caller")
	}
	return s.Send(&grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING})
}
func dialServer(t *testing.T, s *grpc.Server, source TokenSource) *grpc.ClientConn {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	done := make(chan error, 1)
	go func() { done <- s.Serve(listener) }()
	t.Cleanup(func() {
		s.Stop()
		_ = listener.Close()
		if err := <-done; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Error(err)
		}
	})
	options := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() })}
	if source != nil {
		options = append(options, grpc.WithUnaryInterceptor(UnaryClient(source)), grpc.WithStreamInterceptor(StreamClient(source)))
	}
	conn, e := grpc.NewClient("passthrough:///buf", options...)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// TestUsageHTTPToGRPC exercises README wiring with real signatures, a generated
// client and a bufconn server; no fake verifier admits the call.
func TestIntegrationUsageHTTPToGRPC(t *testing.T) {
	now := time.Unix(1700000000, 0)
	userPub, userKey := testKey(t)
	svcPub, svcKey := testKey(t)
	source, e := NewStageSource("stage", StageOptions{KeyFile: writeKey(t, svcKey), Caller: "bank-bff", Issuer: "stage", Clock: func() time.Time { return now }})
	if e != nil {
		t.Fatal(e)
	}
	serviceVerifier, e := NewStageVerifier("stage", VerifyOptions{Issuer: "stage", Audience: "finassist-internal", Clock: func() time.Time { return now }}, map[string]ed25519.PublicKey{"bank-bff": svcPub})
	if e != nil {
		t.Fatal(e)
	}
	uv := userVerifier(t, userPub, &now)
	method := analyticsv1.AnalyticsService_GetAnalytics_FullMethodName
	access, e := NewServer(AccessTable{method: {"bank-bff": User}, userv1.UserInternalService_GetSigningKeys_FullMethodName: {"bank-bff": NoUser}, grpc_health_v1.Health_Watch_FullMethodName: {"bank-bff": NoUser}}, serviceVerifier, uv, nil)
	if e != nil {
		t.Fatal(e)
	}
	server := grpc.NewServer(grpc.ChainUnaryInterceptor(access.Unary()), grpc.ChainStreamInterceptor(access.Stream()))
	api := &analyticsAPI{t: t}
	analyticsv1.RegisterAnalyticsServiceServer(server, api)
	userv1.RegisterUserInternalServiceServer(server, &keysAPI{body: string(jwks(t, map[string]ed25519.PublicKey{"one": userPub}))})
	grpc_health_v1.RegisterHealthServer(server, healthAPI{})
	conn := dialServer(t, server, source)
	client := analyticsv1.NewAnalyticsServiceClient(conn)
	// Bootstrap user keys through the authenticated service-only GetSigningKeys path.
	provider := UserKeys{Client: userv1.NewUserInternalServiceClient(conn)}
	loaded, e := provider.JWKS(context.Background())
	if e != nil || !strings.Contains(string(loaded), "Ed25519") {
		t.Fatal(string(loaded), e)
	}
	middleware, e := NewHTTP(uv, func(w http.ResponseWriter, _ *http.Request, e error) {
		rest, ok := finerr.ToREST(e)
		if !ok || rest.Code != "INVALID_TOKEN" {
			t.Fatal(e)
		}
		w.WriteHeader(rest.Spec.HTTPStatus)
	})
	if e != nil {
		t.Fatal(e)
	}
	raw := sign(t, userKey, jwt.SigningMethodEdDSA, "one", baseClaims(now))
	handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var header metadata.MD
		_, e := client.GetAnalytics(r.Context(), &analyticsv1.GetAnalyticsRequest{}, grpc.Header(&header))
		if e != nil {
			t.Error(e)
			w.WriteHeader(500)
			return
		}
		if header.Get("x-request-id")[0] != "server-r" {
			t.Fatal("response metadata lost")
		}
		w.WriteHeader(204)
	}))
	for _, auth := range []string{"Bearer " + raw, "Bearer invalid", ""} {
		r := httptest.NewRequest("GET", "/v1/analytics", nil)
		r.Header.Set("Authorization", auth)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		want := 401
		if auth == "Bearer "+raw {
			want = 204
		}
		if w.Code != want {
			t.Fatalf("status=%d want=%d", w.Code, want)
		}
	}
	if api.calls.Load() != 1 {
		t.Fatal("rejected HTTP request reached handler")
	}
	// Raw generated clients cannot skip service authentication or impersonate a user.
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+raw))
	_, e = client.GetAnalytics(ctx, &analyticsv1.GetAnalyticsRequest{})
	if rest, ok := finerr.ToREST(e); !ok || rest.Code != "INVALID_TOKEN" {
		t.Fatal("unverified outgoing authorization survived", e)
	}
	stream, e := grpc_health_v1.NewHealthClient(conn).Watch(context.Background(), &grpc_health_v1.HealthCheckRequest{})
	if e != nil {
		t.Fatal(e)
	}
	reply, e := stream.Recv()
	if e != nil || reply.Status != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatal(reply, e)
	}
	if _, e = stream.Recv(); !errors.Is(e, io.EOF) {
		t.Fatal(e)
	}
	if _, e = NewHTTP(nil, nil); e == nil {
		t.Fatal("bad HTTP config")
	}
}

func TestUnitMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, e := NewMetrics(reg)
	if e != nil {
		t.Fatal(e)
	}
	m.Reject("user", "expired")
	m.Reject("private-user-id", "secret")
	families, e := reg.Gather()
	if e != nil || len(families) != 1 {
		t.Fatal(e)
	}
	for _, metric := range families[0].Metric {
		for _, label := range metric.Label {
			if label.GetValue() == "secret" || label.GetValue() == "private-user-id" {
				t.Fatal("unbounded metric")
			}
		}
	}
	if _, e = NewMetrics(reg); e == nil {
		t.Fatal("duplicate metrics ignored")
	}
	if _, e = NewMetrics(nil); e == nil {
		t.Fatal("nil registry")
	}
}

func TestIntegrationUsageKubernetesSystemCall(t *testing.T) {
	now := time.Unix(1700000000, 0)
	pub, key := testKey(t)
	cache, _ := NewKeyCache(providerFunc(func(context.Context) ([]byte, error) { return jwks(t, map[string]ed25519.PublicKey{"k": pub}), nil }), func() time.Time { return now }, time.Hour)
	o := VerifyOptions{Issuer: "https://kubernetes.default.svc.cluster.local", Audience: "finassist-internal", Clock: func() time.Time { return now }}
	verifier, e := NewKubernetesVerifier(cache, o, "finassist")
	if e != nil {
		t.Fatal(e)
	}
	access, e := NewServer(AccessTable{analyticsv1.AnalyticsService_GetAnalytics_FullMethodName: {"assistant": System}}, verifier, goodUser(), nil)
	if e != nil {
		t.Fatal(e)
	}
	api := &analyticsAPI{t: t}
	server := grpc.NewServer(grpc.ChainUnaryInterceptor(access.Unary()))
	analyticsv1.RegisterAnalyticsServiceServer(server, api)
	c := claims{RegisteredClaims: baseClaims(now)}
	c.Issuer = o.Issuer
	c.Audience = jwt.ClaimStrings{o.Audience}
	c.Subject = "system:serviceaccount:finassist:assistant"
	c.Kubernetes.Namespace = "finassist"
	c.Kubernetes.ServiceAccount.Name = "assistant"
	raw := sign(t, key, jwt.SigningMethodEdDSA, "k", c)
	path := t.TempDir() + "/token"
	if e = os.WriteFile(path, []byte(raw), 0600); e != nil {
		t.Fatal(e)
	}
	source, _ := NewProjectedSource(path)
	conn := dialServer(t, server, source)
	client := analyticsv1.NewAnalyticsServiceClient(conn)
	if _, e := client.GetAnalytics(context.Background(), &analyticsv1.GetAnalyticsRequest{UserId: proto.String("target-user")}); e != nil {
		t.Fatal(e)
	}
	// A correctly signed token from another namespace is not an authorised service.
	c.Subject = "system:serviceaccount:other:assistant"
	c.Kubernetes.Namespace = "other"
	raw = sign(t, key, jwt.SigningMethodEdDSA, "k", c)
	replacement := path + ".new"
	if e = os.WriteFile(replacement, []byte(raw), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(replacement, path); e != nil {
		t.Fatal(e)
	}
	if _, e = client.GetAnalytics(context.Background(), &analyticsv1.GetAnalyticsRequest{UserId: proto.String("victim")}); status.Code(e) != codes.Unauthenticated || len(status.Convert(e).Details()) != 0 {
		t.Fatal("foreign namespace admitted or details leaked", e)
	}
	if api.calls.Load() != 1 {
		t.Fatal("rejected call reached handler")
	}
}

func TestIntegrationUsageDeniedUserAndCaller(t *testing.T) {
	now := time.Unix(1700000000, 0)
	userPub, userKey := testKey(t)
	bffPub, bffKey := testKey(t)
	otherPub, otherKey := testKey(t)
	o := VerifyOptions{Issuer: "stage", Audience: "finassist-internal", Clock: func() time.Time { return now }}
	services, e := NewStageVerifier("stage", o, map[string]ed25519.PublicKey{"bank-bff": bffPub, "assistant": otherPub})
	if e != nil {
		t.Fatal(e)
	}
	users := userVerifier(t, userPub, &now)
	method := analyticsv1.AnalyticsService_GetAnalytics_FullMethodName
	auth, e := NewServer(AccessTable{method: {"bank-bff": User}}, services, users, nil)
	if e != nil {
		t.Fatal(e)
	}
	api := &analyticsAPI{t: t}
	server := grpc.NewServer(grpc.ChainUnaryInterceptor(auth.Unary()))
	analyticsv1.RegisterAnalyticsServiceServer(server, api)
	c := baseClaims(now)
	c.Issuer = "stage"
	c.Audience = jwt.ClaimStrings{"finassist-internal"}
	c.Subject = "bank-bff"
	serviceToken := sign(t, bffKey, jwt.SigningMethodEdDSA, "bank-bff", c)
	conn := dialServer(t, server, tokenFunc(func(context.Context) (string, error) { return serviceToken, nil }))
	client := analyticsv1.NewAnalyticsServiceClient(conn)
	accessToken := sign(t, userKey, jwt.SigningMethodEdDSA, "one", baseClaims(now))
	httpAuth, _ := NewHTTP(users, func(w http.ResponseWriter, _ *http.Request, _ error) { w.WriteHeader(401) })
	cases := []struct {
		name, userID               string
		foreignCaller, missingRule bool
	}{{name: "foreign user_id", userID: "victim"}, {name: "foreign verified caller", foreignCaller: true}, {name: "method without rule", missingRule: true}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.foreignCaller {
				c.Subject = "assistant"
				serviceToken = sign(t, otherKey, jwt.SigningMethodEdDSA, "assistant", c)
			} else {
				c.Subject = "bank-bff"
				serviceToken = sign(t, bffKey, jwt.SigningMethodEdDSA, "bank-bff", c)
			}
			handler := httpAuth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var e error
				if tc.missingRule {
					_, e = client.ListPeriods(r.Context(), &analyticsv1.ListPeriodsRequest{})
				} else {
					req := &analyticsv1.GetAnalyticsRequest{}
					if tc.userID != "" {
						req.UserId = proto.String(tc.userID)
					}
					_, e = client.GetAnalytics(r.Context(), req)
				}
				if status.Code(e) != codes.PermissionDenied || len(status.Convert(e).Details()) != 0 {
					t.Errorf("not a bare PERMISSION_DENIED: %v", e)
				}
				w.WriteHeader(403)
			}))
			r := httptest.NewRequest("GET", "/v1/analytics", nil)
			r.Header.Set("Authorization", "Bearer "+accessToken)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != 403 || api.calls.Load() != 0 {
				t.Fatal("denied request processed", w.Code, api.calls.Load())
			}
		})
	}
}
