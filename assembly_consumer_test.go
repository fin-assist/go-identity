package identity_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	userv1 "github.com/fin-assist/contracts/gen/go/finassist/user/v1"
	"github.com/fin-assist/go-grpc/client"
	"github.com/fin-assist/go-grpc/reqctx"
	"github.com/fin-assist/go-grpc/server"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	testgrpc "google.golang.org/grpc/interop/grpc_testing"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/fin-assist/go-identity"
)

// clock is a settable injected clock shared by the assemblies of one test.
type clock struct{ now atomic.Int64 }

func newClock() *clock {
	c := &clock{}
	c.now.Store(time.Unix(1700000000, 0).UnixNano())
	return c
}
func (c *clock) Now() time.Time             { return time.Unix(0, c.now.Load()) }
func (c *clock) Advance(d time.Duration)    { c.now.Add(int64(d)) }
func file(t *testing.T, data []byte) string { return writeTemp(t, "f", data) }

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func stageKeysJSON(t *testing.T, keys map[string]ed25519.PublicKey) []byte {
	t.Helper()
	all := []map[string]string{}
	for kid, key := range keys {
		all = append(all, map[string]string{"kid": kid, "kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(key)})
	}
	b, err := json.Marshal(map[string]any{"keys": all})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// kubeToken is a projected ServiceAccount token of name in namespace.
func kubeToken(t *testing.T, key ed25519.PrivateKey, namespace, name string, now time.Time) string {
	t.Helper()
	return sign(t, key, jwt.SigningMethodEdDSA, "cluster", jwt.MapClaims{
		"iss": "https://cluster.test", "aud": "finassist-internal", "sub": "system:serviceaccount:" + namespace + ":" + name,
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"kubernetes.io": map[string]any{"namespace": namespace, "serviceaccount": map[string]any{"name": name}},
	})
}

// cluster is a TLS Kubernetes JWKS endpoint that requires the pod's API token.
type cluster struct {
	server   *httptest.Server
	key      ed25519.PrivateKey
	caFile   string
	apiToken string
	fetched  chan struct{}
	once     sync.Once
	requests atomic.Int32
}

func newCluster(t *testing.T) *cluster {
	t.Helper()
	pub, key := testKey(t)
	c := &cluster{key: key, fetched: make(chan struct{}), apiToken: "api-server-token"}
	c.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+c.apiToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write(jwks(t, map[string]ed25519.PublicKey{"cluster": pub}))
		c.once.Do(func() { close(c.fetched) })
	}))
	t.Cleanup(c.server.Close)
	c.caFile = writeTemp(t, "ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.server.Certificate().Raw}))
	return c
}

func (c *cluster) options(t *testing.T, tokenFile string) identity.KubernetesOptions {
	return identity.KubernetesOptions{
		TokenFile: tokenFile, Issuer: "https://cluster.test", JWKSURL: c.server.URL + "/openid/v1/jwks",
		CAFile: c.caFile, APITokenFile: file(t, []byte(c.apiToken+"\n")),
	}
}

// signingKeys serves user.GetSigningKeys with a rotating body and records the
// service token of every call.
type signingKeys struct {
	userv1.UnimplementedUserInternalServiceServer
	mu      sync.Mutex
	body    []byte
	callers []string
	calls   chan struct{}
}

func (s *signingKeys) set(body []byte) { s.mu.Lock(); s.body = body; s.mu.Unlock() }

func (s *signingKeys) GetSigningKeys(ctx context.Context, _ *userv1.GetSigningKeysRequest) (*userv1.GetSigningKeysResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.callers = append(s.callers, md.Get("x-service-authorization")...)
	select {
	case s.calls <- struct{}{}:
	default:
	}
	return &userv1.GetSigningKeysResponse{JwksJson: string(s.body)}, nil
}

func (s *signingKeys) JWKS(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.body...), nil
}

// serve runs s on bufconn and returns a dialer for it.
func serve(t *testing.T, s *grpc.Server) func(context.Context, string) (net.Conn, error) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	done := make(chan error, 1)
	go func() { done <- s.Serve(lis) }()
	t.Cleanup(func() {
		s.Stop()
		if err := <-done; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Error(err)
		}
	})
	return func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }
}

// dialUser is the documented DialUser of a service: go-grpc client.Dial with the
// assembly's token source, retrying only GetSigningKeys.
func dialUser(dialer func(context.Context, string) (net.Conn, error)) func(identity.TokenSource) (*grpc.ClientConn, error) {
	return func(tokens identity.TokenSource) (*grpc.ClientConn, error) {
		return client.Dial("passthrough:///user", client.Options{
			Peer: "user", Tokens: tokens,
			Retry:       []string{"finassist.user.v1.UserInternalService/GetSigningKeys"},
			DialOptions: []grpc.DialOption{grpc.WithContextDialer(dialer)},
		})
	}
}

func runAssembly(t *testing.T, a *identity.Assembly) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Error("Run must return the context error", err)
		}
		if err := a.Close(); err != nil {
			t.Error(err)
		}
	})
}

func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for", what)
	}
}

func userToken(t *testing.T, key ed25519.PrivateKey, kid, sub string, now time.Time) string {
	t.Helper()
	return sign(t, key, jwt.SigningMethodEdDSA, kid, jwt.RegisteredClaims{Issuer: "user", Subject: sub, Audience: jwt.ClaimStrings{"finassist"}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute))})
}

func TestIntegrationAssemblyProdKubernetesAndUserKeys(t *testing.T) {
	clk := newClock()
	k8s := newCluster(t)
	ownToken := kubeToken(t, k8s.key, "finassist", "analytics", clk.Now())
	userPub, userKey := testKey(t)
	keys := &signingKeys{body: jwks(t, map[string]ed25519.PublicKey{"one": userPub}), calls: make(chan struct{}, 1)}
	g := grpc.NewServer()
	userv1.RegisterUserInternalServiceServer(g, keys)
	reg := prometheus.NewRegistry()
	a, err := identity.NewAssembly(identity.AssemblyOptions{
		Env: "prod", Service: "analytics", UserIssuer: "user", UserAudience: "finassist",
		DialUser:   dialUser(serve(t, g)),
		Kubernetes: k8s.options(t, file(t, []byte(ownToken))),
		Clock:      clk.Now, Registerer: reg,
	})
	if err != nil {
		t.Fatal(err)
	}
	if k8s.requests.Load() != 0 || len(keys.callers) != 0 {
		t.Fatal("construction must not fetch keys")
	}
	runAssembly(t, a)
	// Run loads both snapshots in the background before the first request.
	waitFor(t, k8s.fetched, "Kubernetes JWKS")
	waitFor(t, keys.calls, "GetSigningKeys")
	keys.mu.Lock()
	if len(keys.callers) != 1 || keys.callers[0] != "Bearer "+ownToken {
		t.Fatal("GetSigningKeys must carry this service's projected token", keys.callers)
	}
	keys.mu.Unlock()

	if caller, err := a.VerifyService(t.Context(), kubeToken(t, k8s.key, "finassist", "bank-bff", clk.Now())); err != nil || caller != "bank-bff" {
		t.Fatal(caller, err)
	}
	if caller, err := a.VerifyService(t.Context(), kubeToken(t, k8s.key, "other", "bank-bff", clk.Now())); err == nil || caller != "" {
		t.Fatal("foreign namespace admitted")
	}
	if sub, err := a.VerifyUser(t.Context(), userToken(t, userKey, "one", "user-1", clk.Now())); err != nil || sub != "user-1" {
		t.Fatal(sub, err)
	}
	if token, err := a.Token(t.Context()); err != nil || token != ownToken {
		t.Fatal("outgoing token is not the projected file", err)
	}

	// Rotation: user publishes a new key; after the one-minute limiter an unknown kid refreshes.
	newPub, newKey := testKey(t)
	keys.set(jwks(t, map[string]ed25519.PublicKey{"one": userPub, "two": newPub}))
	clk.Advance(61 * time.Second)
	if sub, err := a.VerifyUser(t.Context(), userToken(t, newKey, "two", "user-2", clk.Now())); err != nil || sub != "user-2" {
		t.Fatal("rotated user key not loaded", sub, err)
	}
	// A key outside the trusted snapshot is never accepted.
	_, forged := testKey(t)
	if _, err := a.VerifyUser(t.Context(), userToken(t, forged, "one", "user-1", clk.Now())); status.Code(err) != codes.Unauthenticated {
		t.Fatal("forged user token", err)
	}
	if got := metricValues(t, reg, "finassist_identity_jwks_skipped_keys"); len(got) != 12 {
		t.Fatal("both observed caches must report every skip reason", got)
	}
}

func TestIntegrationAssemblyProdJWKSNeedsAPIToken(t *testing.T) {
	clk := newClock()
	k8s := newCluster(t)
	userPub, _ := testKey(t)
	options := k8s.options(t, file(t, []byte(kubeToken(t, k8s.key, "finassist", "analytics", clk.Now()))))
	// The finassist-internal token is not an API-server credential.
	options.APITokenFile = file(t, []byte("finassist-internal-token"))
	a, err := identity.NewAssembly(identity.AssemblyOptions{
		Env: "prod", Service: "analytics", UserIssuer: "user", UserAudience: "finassist",
		UserKeys:   &signingKeys{body: jwks(t, map[string]ed25519.PublicKey{"one": userPub})},
		Kubernetes: options, Clock: clk.Now, Registerer: prometheus.NewRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	caller, err := a.VerifyService(t.Context(), kubeToken(t, k8s.key, "finassist", "bank-bff", clk.Now()))
	if err == nil || caller != "" || k8s.requests.Load() != 1 {
		t.Fatal("JWKS fetch without the API token must not admit a caller", caller, err)
	}
}

func TestIntegrationAssemblyStageOverUserRPC(t *testing.T) {
	clk := newClock()
	userPub, userKey := testKey(t)
	analyticsPub, analyticsKey := testKey(t)
	keys := &signingKeys{body: jwks(t, map[string]ed25519.PublicKey{"one": userPub}), calls: make(chan struct{}, 1)}
	g := grpc.NewServer()
	userv1.RegisterUserInternalServiceServer(g, keys)
	public := file(t, stageKeysJSON(t, map[string]ed25519.PublicKey{"analytics": analyticsPub}))
	a, err := identity.NewAssembly(identity.AssemblyOptions{
		Env: "stage", Service: "analytics", UserIssuer: "user", UserAudience: "finassist",
		DialUser: dialUser(serve(t, g)),
		Stage:    identity.StageKeyFiles{Issuer: "stage", SigningKeyFile: writeKey(t, analyticsKey), PublicKeysFile: public},
		Clock:    clk.Now, Registerer: prometheus.NewRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	runAssembly(t, a)
	waitFor(t, keys.calls, "GetSigningKeys")
	keys.mu.Lock()
	sent := keys.callers[0]
	keys.mu.Unlock()
	// The user RPC carries a stage JWT signed with this service's file key.
	if caller, err := a.VerifyService(t.Context(), sent[len("Bearer "):]); err != nil || caller != "analytics" {
		t.Fatal("GetSigningKeys did not carry the stage token", caller, err)
	}
	if sub, err := a.VerifyUser(t.Context(), userToken(t, userKey, "one", "user-1", clk.Now())); err != nil || sub != "user-1" {
		t.Fatal(sub, err)
	}
}

// --- Consumer wiring through the go-grpc server chain ------------------------

type recorder struct {
	testgrpc.UnimplementedTestServiceServer
	calls atomic.Int32
	seen  chan [2]string
}

func (r *recorder) record(ctx context.Context) {
	r.calls.Add(1)
	user, _ := reqctx.UserID(ctx)
	r.seen <- [2]string{reqctx.Caller(ctx), user}
}

func (r *recorder) EmptyCall(ctx context.Context, _ *testgrpc.Empty) (*testgrpc.Empty, error) {
	r.record(ctx)
	return &testgrpc.Empty{}, nil
}

func (r *recorder) UnaryCall(ctx context.Context, _ *testgrpc.SimpleRequest) (*testgrpc.SimpleResponse, error) {
	r.record(ctx)
	return &testgrpc.SimpleResponse{}, nil
}

// grpcServer is a go-grpc server whose Services and Users come from a, as in a
// service's internal/app. EmptyCall is a bank-bff user call, UnaryCall an
// assistant system call.
func grpcServer(t *testing.T, a *identity.Assembly, register func(*grpc.Server)) func(context.Context, string) (net.Conn, error) {
	t.Helper()
	srv, err := server.New(server.Options{}, server.Deps{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Metrics: prometheus.NewRegistry(),
		Policy: server.Policy{
			"/grpc.testing.TestService/*":                           {Callers: []string{"bank-bff"}, Model: server.ModelUser},
			"/grpc.testing.TestService/UnaryCall":                   {Callers: []string{"assistant"}, Model: server.ModelSystem},
			"/finassist.user.v1.UserInternalService/GetSigningKeys": {Callers: []string{server.AnyCaller}, Model: server.ModelNoUser},
			"/finassist.user.v1.UserInternalService/*":              {Callers: []string{"bank-bff"}, Model: server.ModelUser},
		},
		Services: a, Users: a, Tombstones: server.NoTombstones{},
	})
	if err != nil {
		t.Fatal(err)
	}
	register(srv.GRPC())
	lis := bufconn.Listen(1 << 20)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(lis) }()
	t.Cleanup(func() {
		srv.GRPC().Stop()
		if err := <-done; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Error(err)
		}
	})
	return func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }
}

func rawConn(t *testing.T, dialer func(context.Context, string) (net.Conn, error)) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///svc", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(dialer))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func outgoing(t *testing.T, service, user string) context.Context {
	md := metadata.MD{}
	if service != "" {
		md.Set("x-service-authorization", "Bearer "+service)
	}
	if user != "" {
		md.Set("authorization", "Bearer "+user)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	return metadata.NewOutgoingContext(ctx, md)
}

type refusal struct {
	name    string
	ctx     context.Context
	code    codes.Code
	reason  string
	viaUser bool // EmptyCall (user model) instead of UnaryCall (system model)
}

func expectRefusals(t *testing.T, conn *grpc.ClientConn, handler *recorder, cases []refusal) {
	t.Helper()
	c := testgrpc.NewTestServiceClient(conn)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := handler.calls.Load()
			var err error
			if tc.viaUser {
				_, err = c.EmptyCall(tc.ctx, &testgrpc.Empty{})
			} else {
				_, err = c.UnaryCall(tc.ctx, &testgrpc.SimpleRequest{})
			}
			if status.Code(err) != tc.code || server.Reason(err) != tc.reason {
				t.Fatalf("got %v (reason %q), want %v %q", status.Code(err), server.Reason(err), tc.code, tc.reason)
			}
			if handler.calls.Load() != before {
				t.Fatal("refused call reached the handler")
			}
		})
	}
}

func TestAPIAssemblyProdThroughGoGRPCServer(t *testing.T) {
	clk := newClock()
	k8s := newCluster(t)
	userPub, userKey := testKey(t)
	keys := &signingKeys{body: jwks(t, map[string]ed25519.PublicKey{"one": userPub})}
	kube := func(namespace, name string) string { return kubeToken(t, k8s.key, namespace, name, clk.Now()) }

	// The user service: local signing keys, verifies the callers of GetSigningKeys.
	userAssembly, err := identity.NewAssembly(identity.AssemblyOptions{
		Env: "prod", Service: "user", UserIssuer: "user", UserAudience: "finassist", UserKeys: keys,
		Kubernetes: k8s.options(t, file(t, []byte(kube("finassist", "user")))), Clock: clk.Now, Registerer: prometheus.NewRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = userAssembly.Close() })
	userDialer := grpcServer(t, userAssembly, func(s *grpc.Server) { userv1.RegisterUserInternalServiceServer(s, keys) })

	// analytics: fetches user keys through user's real access chain.
	analytics, err := identity.NewAssembly(identity.AssemblyOptions{
		Env: "prod", Service: "analytics", UserIssuer: "user", UserAudience: "finassist", DialUser: dialUser(userDialer),
		Kubernetes: k8s.options(t, file(t, []byte(kube("finassist", "analytics")))), Clock: clk.Now, Registerer: prometheus.NewRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	runAssembly(t, analytics)
	handler := &recorder{seen: make(chan [2]string, 1)}
	conn := rawConn(t, grpcServer(t, analytics, func(s *grpc.Server) { testgrpc.RegisterTestServiceServer(s, handler) }))
	c := testgrpc.NewTestServiceClient(conn)

	user := userToken(t, userKey, "one", "user-1", clk.Now())
	if _, err := c.EmptyCall(outgoing(t, kube("finassist", "bank-bff"), user), &testgrpc.Empty{}); err != nil {
		t.Fatal(err)
	}
	if got := <-handler.seen; got != [2]string{"bank-bff", "user-1"} {
		t.Fatal("handler identity", got)
	}
	if _, err := c.UnaryCall(outgoing(t, kube("finassist", "assistant"), ""), &testgrpc.SimpleRequest{}); err != nil {
		t.Fatal(err)
	}
	if got := <-handler.seen; got != [2]string{"assistant", ""} {
		t.Fatal("system call identity", got)
	}

	_, forgedUser := testKey(t)
	_, forgedCluster := testKey(t)
	expired := userToken(t, userKey, "one", "user-1", clk.Now().Add(-time.Hour))
	expectRefusals(t, conn, handler, []refusal{
		{"forged user token", outgoing(t, kube("finassist", "bank-bff"), userToken(t, forgedUser, "one", "user-1", clk.Now())), codes.Unauthenticated, "INVALID_TOKEN", true},
		{"expired user token", outgoing(t, kube("finassist", "bank-bff"), expired), codes.Unauthenticated, "INVALID_TOKEN", true},
		{"service token as user token", outgoing(t, kube("finassist", "bank-bff"), kube("finassist", "bank-bff")), codes.Unauthenticated, "INVALID_TOKEN", true},
		{"foreign caller", outgoing(t, kube("finassist", "billing"), ""), codes.PermissionDenied, "", false},
		{"user caller on system method", outgoing(t, kube("finassist", "bank-bff"), user), codes.PermissionDenied, "", false},
		{"foreign namespace", outgoing(t, kube("other", "assistant"), ""), codes.Unauthenticated, "", false},
		{"forged cluster key", outgoing(t, kubeToken(t, forgedCluster, "finassist", "assistant", clk.Now()), ""), codes.Unauthenticated, "", false},
		{"user token as service token", outgoing(t, user, ""), codes.Unauthenticated, "", false},
		{"no service token", outgoing(t, "", user), codes.Unauthenticated, "", true},
	})
}

func TestAPIAssemblyStageThroughGoGRPCServer(t *testing.T) {
	clk := newClock()
	userPub, userKey := testKey(t)
	keys := &signingKeys{body: jwks(t, map[string]ed25519.PublicKey{"one": userPub})}
	public, private := map[string]ed25519.PublicKey{}, map[string]ed25519.PrivateKey{}
	for _, name := range []string{"user", "analytics", "assistant", "bank-bff"} {
		public[name], private[name] = testKey(t)
	}
	publicFile := file(t, stageKeysJSON(t, public))
	stage := func(service string) identity.StageKeyFiles {
		return identity.StageKeyFiles{Issuer: "stage", SigningKeyFile: writeKey(t, private[service]), PublicKeysFile: publicFile}
	}
	userAssembly, err := identity.NewAssembly(identity.AssemblyOptions{
		Env: "stage", Service: "user", UserIssuer: "user", UserAudience: "finassist", UserKeys: keys,
		Stage: stage("user"), Clock: clk.Now, Registerer: prometheus.NewRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = userAssembly.Close() })
	userDialer := grpcServer(t, userAssembly, func(s *grpc.Server) { userv1.RegisterUserInternalServiceServer(s, keys) })
	newService := func(name string) *identity.Assembly {
		a, err := identity.NewAssembly(identity.AssemblyOptions{
			Env: "stage", Service: name, UserIssuer: "user", UserAudience: "finassist", DialUser: dialUser(userDialer),
			Stage: stage(name), Clock: clk.Now, Registerer: prometheus.NewRegistry(),
		})
		if err != nil {
			t.Fatal(err)
		}
		runAssembly(t, a)
		return a
	}
	analytics, assistant := newService("analytics"), newService("assistant")
	handler := &recorder{seen: make(chan [2]string, 1)}
	analyticsDialer := grpcServer(t, analytics, func(s *grpc.Server) { testgrpc.RegisterTestServiceServer(s, handler) })

	// assistant calls analytics through go-grpc client with its assembly as the token source.
	conn, err := client.Dial("passthrough:///analytics", client.Options{Peer: "analytics", Tokens: assistant, DialOptions: []grpc.DialOption{grpc.WithContextDialer(analyticsDialer)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := testgrpc.NewTestServiceClient(conn).UnaryCall(t.Context(), &testgrpc.SimpleRequest{}); err != nil {
		t.Fatal(err)
	}
	if got := <-handler.seen; got != [2]string{"assistant", ""} {
		t.Fatal(got)
	}

	stageToken := func(signer, kid, sub string, ttl time.Duration) string {
		now := clk.Now()
		return sign(t, private[signer], jwt.SigningMethodEdDSA, kid, jwt.RegisteredClaims{Issuer: "stage", Subject: sub, Audience: jwt.ClaimStrings{"finassist-internal"}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(ttl))})
	}
	raw := rawConn(t, analyticsDialer)
	user := userToken(t, userKey, "one", "user-1", clk.Now())
	if _, err := testgrpc.NewTestServiceClient(raw).EmptyCall(outgoing(t, stageToken("bank-bff", "bank-bff", "bank-bff", time.Minute), user), &testgrpc.Empty{}); err != nil {
		t.Fatal(err)
	}
	if got := <-handler.seen; got != [2]string{"bank-bff", "user-1"} {
		t.Fatal(got)
	}
	_, unknown := testKey(t)
	expectRefusals(t, raw, handler, []refusal{
		{"bank-bff key naming assistant", outgoing(t, stageToken("bank-bff", "assistant", "assistant", time.Minute), ""), codes.Unauthenticated, "", false},
		{"kid and sub differ", outgoing(t, stageToken("bank-bff", "bank-bff", "assistant", time.Minute), ""), codes.Unauthenticated, "", false},
		{"long-lived stage token", outgoing(t, stageToken("assistant", "assistant", "assistant", time.Hour), ""), codes.Unauthenticated, "", false},
		{"unknown stage key", outgoing(t, sign(t, unknown, jwt.SigningMethodEdDSA, "billing", jwt.RegisteredClaims{Issuer: "stage", Subject: "billing", Audience: jwt.ClaimStrings{"finassist-internal"}, IssuedAt: jwt.NewNumericDate(clk.Now()), ExpiresAt: jwt.NewNumericDate(clk.Now().Add(time.Minute))}), ""), codes.Unauthenticated, "", false},
		{"foreign stage caller", outgoing(t, stageToken("user", "user", "user", time.Minute), ""), codes.PermissionDenied, "", false},
		{"forged user token", outgoing(t, stageToken("bank-bff", "bank-bff", "bank-bff", time.Minute), userToken(t, unknown, "one", "user-1", clk.Now())), codes.Unauthenticated, "INVALID_TOKEN", true},
	})
}

func TestAPIAssemblyRefusesOtherEnvironments(t *testing.T) {
	_, key := testKey(t)
	pub, _ := testKey(t)
	for _, env := range []string{"dev", "", "production", "STAGE"} {
		_, err := identity.NewAssembly(identity.AssemblyOptions{
			Env: env, Service: "analytics", UserIssuer: "user", UserAudience: "finassist",
			UserKeys: &signingKeys{body: jwks(t, map[string]ed25519.PublicKey{"one": pub})},
			Stage:    identity.StageKeyFiles{Issuer: "stage", SigningKeyFile: writeKey(t, key), PublicKeysFile: file(t, stageKeysJSON(t, map[string]ed25519.PublicKey{"analytics": pub}))},
			Clock:    time.Now, Registerer: prometheus.NewRegistry(),
		})
		if err == nil {
			t.Fatalf("env %q accepted", env)
		}
	}
	// Stage key files are a stage credential: prod refuses them even with valid Kubernetes settings.
	_, err := identity.NewAssembly(identity.AssemblyOptions{
		Env: "prod", Service: "analytics", UserIssuer: "user", UserAudience: "finassist",
		UserKeys:   &signingKeys{body: jwks(t, map[string]ed25519.PublicKey{"one": pub})},
		Kubernetes: identity.KubernetesOptions{TokenFile: "/run/finassist/token"},
		Stage:      identity.StageKeyFiles{SigningKeyFile: writeKey(t, key)},
		Clock:      time.Now, Registerer: prometheus.NewRegistry(),
	})
	if err == nil {
		t.Fatal("stage key accepted in prod")
	}
}

func TestIntegrationAssemblyRejectsJWKSFromAnotherCA(t *testing.T) {
	clk := newClock()
	k8s := newCluster(t)
	userPub, _ := testKey(t)
	options := k8s.options(t, file(t, []byte(kubeToken(t, k8s.key, "finassist", "analytics", clk.Now()))))
	// Every httptest server shares one certificate, so the foreign CA is generated here.
	options.CAFile = writeTemp(t, "other-ca.crt", foreignCA(t))
	a, err := identity.NewAssembly(identity.AssemblyOptions{
		Env: "prod", Service: "analytics", UserIssuer: "user", UserAudience: "finassist",
		UserKeys:   &signingKeys{body: jwks(t, map[string]ed25519.PublicKey{"one": userPub})},
		Kubernetes: options, Clock: clk.Now, Registerer: prometheus.NewRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	caller, err := a.VerifyService(t.Context(), kubeToken(t, k8s.key, "finassist", "bank-bff", clk.Now()))
	if err == nil || caller != "" {
		t.Fatal("JWKS from an untrusted certificate admitted a caller", caller)
	}
	// The handshake fails before any HTTP request, so the API token never leaves the pod.
	if k8s.requests.Load() != 0 {
		t.Fatal("request sent to a server outside the configured CA")
	}
}

// foreignCA is a self-signed CA that signed none of the test servers.
func foreignCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "foreign CA"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<32, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// proxyChildEnv marks the child process of TestIntegrationAssemblyIgnoresProxyEnvironment.
const proxyChildEnv = "GO_IDENTITY_PROXY_CHILD"

// The proxy environment must be set before the process starts: net/http reads it
// once per process, so the check runs in a child copy of the test binary.
func TestIntegrationAssemblyIgnoresProxyEnvironment(t *testing.T) {
	if os.Getenv(proxyChildEnv) == "1" {
		clk := newClock()
		k8s := newCluster(t)
		userPub, _ := testKey(t)
		options := k8s.options(t, file(t, []byte(kubeToken(t, k8s.key, "finassist", "analytics", clk.Now()))))
		// Not a loopback host: net/http never proxies loopback, so it would hide a regression.
		options.JWKSURL = "https://kubernetes.finassist.invalid/openid/v1/jwks"
		a, err := identity.NewAssembly(identity.AssemblyOptions{
			Env: "prod", Service: "analytics", UserIssuer: "user", UserAudience: "finassist",
			UserKeys:   &signingKeys{body: jwks(t, map[string]ed25519.PublicKey{"one": userPub})},
			Kubernetes: options, Clock: clk.Now, Registerer: prometheus.NewRegistry(),
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = a.Close() }()
		if caller, err := a.VerifyService(t.Context(), kubeToken(t, k8s.key, "finassist", "bank-bff", clk.Now())); err == nil || caller != "" {
			t.Fatal("unreachable JWKS admitted a caller", caller)
		}
		return
	}
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxied.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	// A child that matches no test exits with PASS, so the run must name this test
	// and its verbose output must show that exactly this test passed.
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), proxyChildEnv+"=1", "HTTPS_PROXY="+proxy.URL, "https_proxy="+proxy.URL, "HTTP_PROXY="+proxy.URL, "http_proxy="+proxy.URL, "NO_PROXY=", "no_proxy=")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "--- PASS: "+t.Name()+" ") {
		t.Fatalf("child did not run %s:\n%s", t.Name(), out)
	}
	if proxied.Load() != 0 {
		t.Fatal("the JWKS request went through the proxy from the environment")
	}
}
