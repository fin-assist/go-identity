package identity_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

	"github.com/fin-assist/go-identity"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	p, k, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return p, k
}
func jwks(t *testing.T, keys map[string]ed25519.PublicKey) []byte {
	t.Helper()
	all := []map[string]string{}
	for kid, key := range keys {
		all = append(all, map[string]string{"kid": kid, "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "x": base64.RawURLEncoding.EncodeToString(key)})
	}
	b, e := json.Marshal(map[string]any{"keys": all})
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func sign(t *testing.T, key any, method jwt.SigningMethod, kid string, c jwt.Claims) string {
	t.Helper()
	token := jwt.NewWithClaims(method, c)
	if kid != "" {
		token.Header["kid"] = kid
	}
	s, e := token.SignedString(key)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func opts(now *time.Time) identity.VerifyOptions {
	return identity.VerifyOptions{Issuer: "user", Audience: "finassist", Clock: func() time.Time { return *now }}
}
func baseClaims(now time.Time) jwt.RegisteredClaims {
	return jwt.RegisteredClaims{Issuer: "user", Subject: "user-1", Audience: jwt.ClaimStrings{"finassist"}, ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)), IssuedAt: jwt.NewNumericDate(now)}
}
func writeKey(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	b, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	if e = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), 0600); e != nil {
		t.Fatal(e)
	}
	return path
}

func userVerifier(t *testing.T, pub ed25519.PublicKey, now *time.Time) *identity.UserVerifier {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(jwks(t, map[string]ed25519.PublicKey{"one": pub}))
	}))
	t.Cleanup(server.Close)
	provider, err := identity.NewHTTPKeys(server.Client(), server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := identity.NewKeyCache(provider, func() time.Time { return *now }, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := identity.NewUserVerifier(cache, opts(now))
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

type tokenFunc func(context.Context) (string, error)

func (f tokenFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

type analyticsAPI struct {
	analyticsv1.UnimplementedAnalyticsServiceServer
	calls atomic.Int32
	t     *testing.T
}

func (a *analyticsAPI) GetAnalytics(ctx context.Context, r *analyticsv1.GetAnalyticsRequest) (*analyticsv1.GetAnalyticsResponse, error) {
	a.calls.Add(1)
	c, ok := identity.Caller(ctx)
	if !ok {
		a.t.Fatal("missing caller")
	}
	if c == "bank-bff" {
		if id, ok := identity.UserID(ctx); !ok || id != "user-1" {
			a.t.Fatal("missing user")
		}
	} else {
		if _, e := identity.SystemUserID(ctx, r.GetUserId()); e != nil {
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
	if _, ok := identity.Caller(s.Context()); !ok {
		return errors.New("missing caller")
	}
	return s.Send(&grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING})
}
func dialServer(t *testing.T, s *grpc.Server, source identity.TokenSource) *grpc.ClientConn {
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
		options = append(options, grpc.WithUnaryInterceptor(identity.UnaryClient(source)), grpc.WithStreamInterceptor(identity.StreamClient(source)))
	}
	conn, e := grpc.NewClient("passthrough:///buf", options...)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestAPIConsumerHTTPToGRPC(t *testing.T) {
	now := time.Unix(1700000000, 0)
	userPub, userKey := testKey(t)
	svcPub, svcKey := testKey(t)
	source, e := identity.NewStageSource("stage", identity.StageOptions{KeyFile: writeKey(t, svcKey), Caller: "bank-bff", Issuer: "stage", Clock: func() time.Time { return now }})
	if e != nil {
		t.Fatal(e)
	}
	serviceVerifier, e := identity.NewStageVerifier("stage", identity.VerifyOptions{Issuer: "stage", Audience: "finassist-internal", Clock: func() time.Time { return now }}, map[string]ed25519.PublicKey{"bank-bff": svcPub})
	if e != nil {
		t.Fatal(e)
	}
	uv := userVerifier(t, userPub, &now)
	method := analyticsv1.AnalyticsService_GetAnalytics_FullMethodName
	access, e := identity.NewServer(identity.AccessTable{method: {"bank-bff": identity.User}, userv1.UserInternalService_GetSigningKeys_FullMethodName: {"bank-bff": identity.NoUser}, grpc_health_v1.Health_Watch_FullMethodName: {"bank-bff": identity.NoUser}}, serviceVerifier, uv, nil)
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
	provider := identity.UserKeys{Client: userv1.NewUserInternalServiceClient(conn)}
	loaded, e := provider.JWKS(context.Background())
	if e != nil || !strings.Contains(string(loaded), "Ed25519") {
		t.Fatal(string(loaded), e)
	}
	middleware, e := identity.NewHTTP(uv, func(w http.ResponseWriter, _ *http.Request, e error) {
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
	if _, e = identity.NewHTTP(nil, nil); e == nil {
		t.Fatal("bad HTTP config")
	}
}
func TestAPIConsumerDeniedUserAndCaller(t *testing.T) {
	now := time.Unix(1700000000, 0)
	userPub, userKey := testKey(t)
	bffPub, bffKey := testKey(t)
	otherPub, otherKey := testKey(t)
	o := identity.VerifyOptions{Issuer: "stage", Audience: "finassist-internal", Clock: func() time.Time { return now }}
	services, e := identity.NewStageVerifier("stage", o, map[string]ed25519.PublicKey{"bank-bff": bffPub, "assistant": otherPub})
	if e != nil {
		t.Fatal(e)
	}
	users := userVerifier(t, userPub, &now)
	method := analyticsv1.AnalyticsService_GetAnalytics_FullMethodName
	auth, e := identity.NewServer(identity.AccessTable{method: {"bank-bff": identity.User}}, services, users, nil)
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
	httpAuth, _ := identity.NewHTTP(users, func(w http.ResponseWriter, _ *http.Request, _ error) { w.WriteHeader(401) })
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

// The consumer pins TLS trust, issuer and audience; hostile token metadata cannot select its key endpoint.
func TestAPIUserVerificationTrustBoundaries(t *testing.T) {
	now := time.Unix(1700000000, 0)
	pub, key := testKey(t)
	verifier := userVerifier(t, pub, &now)
	cases := []struct {
		name   string
		change func(*jwt.RegisteredClaims)
		kid    string
		mutate func(*jwt.Token)
	}{
		{name: "valid", kid: "one"},
		{name: "expired", kid: "one", change: func(c *jwt.RegisteredClaims) { c.ExpiresAt = jwt.NewNumericDate(now) }},
		{name: "wrong issuer", kid: "one", change: func(c *jwt.RegisteredClaims) { c.Issuer = "foreign" }},
		{name: "wrong audience", kid: "one", change: func(c *jwt.RegisteredClaims) { c.Audience = jwt.ClaimStrings{"foreign"} }},
		{name: "empty subject", kid: "one", change: func(c *jwt.RegisteredClaims) { c.Subject = " " }},
		{name: "subject too long", kid: "one", change: func(c *jwt.RegisteredClaims) { c.Subject = strings.Repeat("u", 257) }},
		{name: "future issued", kid: "one", change: func(c *jwt.RegisteredClaims) { c.IssuedAt = jwt.NewNumericDate(now.Add(time.Minute)) }},
		{name: "future nbf", kid: "one", change: func(c *jwt.RegisteredClaims) { c.NotBefore = jwt.NewNumericDate(now.Add(time.Minute)) }},
		{name: "missing expiration", kid: "one", change: func(c *jwt.RegisteredClaims) { c.ExpiresAt = nil }},
		{name: "missing key id"}, {name: "unknown key", kid: "unknown"}, {name: "oversize kid", kid: strings.Repeat("k", 257)},
		{name: "critical extension", kid: "one", mutate: func(token *jwt.Token) { token.Header["crit"] = []string{"untrusted"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := baseClaims(now)
			if tc.change != nil {
				tc.change(&c)
			}
			token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
			if tc.kid != "" {
				token.Header["kid"] = tc.kid
			}
			if tc.mutate != nil {
				tc.mutate(token)
			}
			raw, err := token.SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			id, err := verifier.VerifyUser(t.Context(), raw)
			if tc.name == "valid" {
				if err != nil || id != "user-1" {
					t.Fatal(id, err)
				}
			} else {
				rest, ok := finerr.ToREST(err)
				if !ok || rest.Code != "INVALID_TOKEN" || id != "" {
					t.Fatal("untrusted token admitted", id, err)
				}
			}
		})
	}
	for _, raw := range []string{"", "malformed", strings.Repeat("x", 16385), sign(t, key, jwt.SigningMethodEdDSA, "one", baseClaims(now)) + "tampered"} {
		if id, err := verifier.VerifyUser(t.Context(), raw); err == nil || id != "" {
			t.Fatal("invalid token admitted")
		}
	}
}

func TestIntegrationTLSKeyAlgorithmsAndMalformedSnapshots(t *testing.T) {
	now := time.Unix(1700000000, 0)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x := base64.RawURLEncoding.EncodeToString(ec.X.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(ec.Y.FillBytes(make([]byte, 32)))
	valid := `{"keys":[{"kid":"ec","kty":"EC","crv":"P-256","alg":"ES256","x":"` + x + `","y":"` + y + `"}]}`
	bodies := []string{valid, `{}`, `null`, `{"keys":[]}`, `{"keys":[{"kid":"x","kty":"unknown"}]}`, `{"keys":[{"kid":"x","kty":"OKP","crv":"Ed25519","x":"bad"}]}`, `{"keys":[{"kid":"x","kty":"RSA","n":"bad","e":"AQAB"}]}`, strings.Replace(valid, y, "bad", 1), strings.Replace(valid, x, base64.RawURLEncoding.EncodeToString(make([]byte, 32)), 1), strings.Replace(valid, `"kid":"ec"`, `"kid":""`, 1), strings.Replace(valid, `"alg":"ES256"`, `"use":"enc","alg":"ES256"`, 1)}
	for i, body := range bodies {
		t.Run(big.NewInt(int64(i)).String(), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			provider, e := identity.NewHTTPKeys(server.Client(), server.URL, nil)
			if e != nil {
				t.Fatal(e)
			}
			cache, e := identity.NewKeyCache(provider, func() time.Time { return now }, time.Minute*2)
			if e != nil {
				t.Fatal(e)
			}
			v, e := identity.NewUserVerifier(cache, identity.VerifyOptions{Issuer: "user", Audience: "finassist", Clock: func() time.Time { return now }})
			if e != nil {
				t.Fatal(e)
			}
			id, e := v.VerifyUser(t.Context(), sign(t, ec, jwt.SigningMethodES256, "ec", baseClaims(now)))
			if i == 0 {
				if e != nil || id != "user-1" {
					t.Fatal(id, e)
				}
			} else if e == nil || id != "" {
				t.Fatal("bad snapshot trusted")
			}
		})
	}
}

func TestIntegrationMetricsBoundedRegistration(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics, err := identity.NewMetrics(reg)
	if err != nil {
		t.Fatal(err)
	}
	metrics.Reject("user", "expired")
	metrics.Reject("private-user", "private-token")
	families, err := reg.Gather()
	if err != nil || len(families) != 1 {
		t.Fatal(families, err)
	}
	for _, m := range families[0].Metric {
		for _, l := range m.Label {
			if strings.Contains(l.GetValue(), "private") {
				t.Fatal("sensitive metric label")
			}
		}
	}
	if _, err := identity.NewMetrics(reg); err == nil {
		t.Fatal("duplicate registration accepted")
	}
}

func TestAPIStageCredentialLifecycle(t *testing.T) {
	now := time.Unix(1700000000, 0)
	pub, key := testKey(t)
	clock := func() time.Time { return now }
	path := writeKey(t, key)
	source, err := identity.NewStageSource("stage", identity.StageOptions{KeyFile: path, Caller: "assistant", Issuer: "stage", Clock: clock, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := identity.NewStageVerifier("stage", identity.VerifyOptions{Issuer: "stage", Audience: "finassist-internal", Clock: clock}, map[string]ed25519.PublicKey{"assistant": pub})
	if err != nil {
		t.Fatal(err)
	}
	first, err := source.Token(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if caller, err := verifier.VerifyService(t.Context(), first); err != nil || caller != "assistant" {
		t.Fatal(caller, err)
	}
	cached, err := source.Token(t.Context())
	if err != nil || cached != first {
		t.Fatal("fresh credential not cached", err)
	}
	now = now.Add(49 * time.Second)
	second, err := source.Token(t.Context())
	if err != nil || second == first {
		t.Fatal("credential not refreshed", err)
	}
	now = now.Add(12 * time.Second)
	if _, err := verifier.VerifyService(t.Context(), first); err == nil {
		t.Fatal("expired service token accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if token, err := source.Token(ctx); !errors.Is(err, context.Canceled) || token != "" {
		t.Fatal("cancellation ignored")
	}
	if _, err := identity.NewStageSource("prod", identity.StageOptions{KeyFile: path, Caller: "assistant", Issuer: "stage", Clock: clock}); err == nil {
		t.Fatal("prod admitted stage credential")
	}
	for _, claims := range []jwt.RegisteredClaims{
		{Issuer: "stage", Subject: "bank-bff", Audience: jwt.ClaimStrings{"finassist-internal"}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute))},
		{Issuer: "stage", Subject: "assistant", Audience: jwt.ClaimStrings{"finassist-internal"}, ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute))},
		{Issuer: "stage", Subject: "assistant", Audience: jwt.ClaimStrings{"finassist-internal"}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(6 * time.Minute))},
	} {
		if _, err := verifier.VerifyService(t.Context(), sign(t, key, jwt.SigningMethodEdDSA, "assistant", claims)); err == nil {
			t.Fatal("unbound or excessive service identity admitted")
		}
	}
	for _, contents := range []string{"not PEM", strings.Repeat("x", 8193), string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("secret")}))} {
		bad := filepath.Join(t.TempDir(), "bad.pem")
		if err := os.WriteFile(bad, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := identity.NewStageSource("stage", identity.StageOptions{KeyFile: bad, Caller: "assistant", Issuer: "stage", Clock: clock}); err == nil || strings.Contains(err.Error(), bad) || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid key accepted or leaked", err)
		}
	}
}

func TestAPIProjectedCredentialsFailClosedAndRotate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	source, err := identity.NewProjectedSource(path)
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := source.Token(t.Context()); err == nil || raw != "" || strings.Contains(err.Error(), path) {
		t.Fatal("missing token not sanitized")
	}
	if err := os.WriteFile(path, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if raw, err := source.Token(t.Context()); err != nil || raw != "first" {
			t.Fatal(raw, err)
		}
	}
	replacement := path + ".new"
	if err := os.WriteFile(replacement, []byte("other"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if raw, err := source.Token(t.Context()); err != nil || raw != "other" {
		t.Fatal("rotated file not observed", err)
	}
	for _, body := range []string{"", "bad token", "line\nbreak", strings.Repeat("x", 16387)} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if raw, err := source.Token(t.Context()); err == nil || raw != "" {
			t.Fatal("stale or malformed token returned")
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if raw, err := source.Token(t.Context()); err == nil || raw != "" {
		t.Fatal("deleted token returned stale credential")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := source.Token(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestAPIKeyRotationAndBoundedMetrics(t *testing.T) {
	now := time.Unix(1700000000, 0)
	pub, key := testKey(t)
	newPub, newKey := testKey(t)
	body := jwks(t, map[string]ed25519.PublicKey{"one": pub})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	defer server.Close()
	provider, err := identity.NewHTTPKeys(server.Client(), server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := identity.NewKeyCache(provider, func() time.Time { return now }, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	registry := prometheus.NewRegistry()
	metrics, err := identity.NewMetrics(registry)
	if err != nil {
		t.Fatal(err)
	}
	o := opts(&now)
	o.Observer = metrics
	verifier, err := identity.NewUserVerifier(cache, o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyUser(t.Context(), sign(t, key, jwt.SigningMethodEdDSA, "one", baseClaims(now))); err != nil {
		t.Fatal(err)
	}
	body = jwks(t, map[string]ed25519.PublicKey{"two": newPub})
	now = now.Add(time.Minute)
	if _, err := verifier.VerifyUser(t.Context(), sign(t, newKey, jwt.SigningMethodEdDSA, "two", baseClaims(now))); err != nil {
		t.Fatal("rotated signing key unavailable", err)
	}
	body = []byte("bad snapshot")
	now = now.Add(2 * time.Minute)
	if _, err := verifier.VerifyUser(t.Context(), sign(t, newKey, jwt.SigningMethodEdDSA, "two", baseClaims(now))); err == nil {
		t.Fatal("expired key snapshot trusted after failed refresh")
	}
	families, err := registry.Gather()
	if err != nil || len(families) != 1 || len(families[0].Metric) == 0 {
		t.Fatal("rejection not observed", err)
	}
	for _, m := range families[0].Metric {
		for _, label := range m.Label {
			if strings.Contains(label.GetValue(), "two") {
				t.Fatal("key identifier leaked into metrics")
			}
		}
	}
	if _, err := identity.NewMetrics(registry); err == nil {
		t.Fatal("duplicate metrics accepted")
	}
	if _, err := identity.NewMetrics(nil); err == nil {
		t.Fatal("nil registry accepted")
	}
}

func TestIntegrationKubernetesTLSNamespaceBinding(t *testing.T) {
	now := time.Unix(1700000000, 0)
	pub, key := testKey(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(jwks(t, map[string]ed25519.PublicKey{"cluster": pub}))
	}))
	defer server.Close()
	provider, err := identity.NewHTTPKeys(server.Client(), server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := identity.NewKeyCache(provider, func() time.Time { return now }, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := identity.NewKubernetesVerifier(cache, identity.VerifyOptions{Issuer: "cluster", Audience: "finassist-internal", Clock: func() time.Time { return now }}, "finassist")
	if err != nil {
		t.Fatal(err)
	}
	for _, namespace := range []string{"finassist", "foreign"} {
		claims := jwt.MapClaims{"iss": "cluster", "aud": "finassist-internal", "sub": "system:serviceaccount:" + namespace + ":assistant", "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "kubernetes.io": map[string]any{"namespace": namespace, "serviceaccount": map[string]any{"name": "assistant"}}}
		caller, err := verifier.VerifyService(t.Context(), sign(t, key, jwt.SigningMethodEdDSA, "cluster", claims))
		if namespace == "finassist" {
			if err != nil || caller != "assistant" {
				t.Fatal(caller, err)
			}
		} else if err == nil || caller != "" {
			t.Fatal("foreign namespace admitted")
		}
	}
}

func TestAPIClusterAndUserSigningKeyPolicy(t *testing.T) {
	now := time.Unix(1700000000, 0)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	rsaJWK := map[string]string{"kid": "cluster", "kty": "RSA", "alg": "RS256", "n": enc(rsaKey.N.Bytes()), "e": enc(big.NewInt(int64(rsaKey.E)).Bytes())}
	ecJWK := map[string]string{"kid": "ec", "kty": "EC", "crv": "P-256", "alg": "ES256", "x": enc(ec.X.FillBytes(make([]byte, 32))), "y": enc(ec.Y.FillBytes(make([]byte, 32)))}
	cases := []struct {
		name      string
		jwk       map[string]string
		key       any
		algorithm jwt.SigningMethod
		cluster   bool
		mutate    func(map[string]string)
		valid     bool
	}{
		{name: "cluster RSA", jwk: rsaJWK, key: rsaKey, algorithm: jwt.SigningMethodRS256, cluster: true, valid: true},
		{name: "user ES256", jwk: ecJWK, key: ec, algorithm: jwt.SigningMethodES256, valid: true},
		{name: "RSA weak exponent", jwk: rsaJWK, key: rsaKey, algorithm: jwt.SigningMethodRS256, cluster: true, mutate: func(j map[string]string) { j["e"] = "Ag" }},
		{name: "RSA small modulus", jwk: rsaJWK, key: rsaKey, algorithm: jwt.SigningMethodRS256, cluster: true, mutate: func(j map[string]string) { j["n"] = "AQ" }},
		{name: "bad EC point", jwk: ecJWK, key: ec, algorithm: jwt.SigningMethodES256, mutate: func(j map[string]string) { j["x"] = enc(make([]byte, 32)); j["y"] = enc(make([]byte, 32)) }},
		{name: "bad EC coordinate", jwk: ecJWK, key: ec, algorithm: jwt.SigningMethodES256, mutate: func(j map[string]string) { j["y"] = "bad" }},
		{name: "wrong curve", jwk: ecJWK, key: ec, algorithm: jwt.SigningMethodES256, mutate: func(j map[string]string) { j["crv"] = "P-384" }},
		{name: "encryption key", jwk: ecJWK, key: ec, algorithm: jwt.SigningMethodES256, mutate: func(j map[string]string) { j["use"] = "enc" }},
		{name: "key without id", jwk: ecJWK, key: ec, algorithm: jwt.SigningMethodES256, mutate: func(j map[string]string) { delete(j, "kid") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := map[string]string{}
			for k, v := range tc.jwk {
				j[k] = v
			}
			if tc.mutate != nil {
				tc.mutate(j)
			}
			body, e := json.Marshal(map[string]any{"keys": []map[string]string{j}})
			if e != nil {
				t.Fatal(e)
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
			defer server.Close()
			provider, e := identity.NewHTTPKeys(server.Client(), server.URL, nil)
			if e != nil {
				t.Fatal(e)
			}
			cache, e := identity.NewKeyCache(provider, func() time.Time { return now }, time.Hour)
			if e != nil {
				t.Fatal(e)
			}
			if tc.cluster {
				verifier, e := identity.NewKubernetesVerifier(cache, identity.VerifyOptions{Issuer: "cluster", Audience: "finassist-internal", Clock: func() time.Time { return now }}, "finassist")
				if e != nil {
					t.Fatal(e)
				}
				claims := jwt.MapClaims{"iss": "cluster", "aud": "finassist-internal", "sub": "system:serviceaccount:finassist:assistant", "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "kubernetes.io": map[string]any{"namespace": "finassist", "serviceaccount": map[string]any{"name": "assistant"}}}
				caller, e := verifier.VerifyService(t.Context(), sign(t, tc.key, tc.algorithm, tc.jwk["kid"], claims))
				if tc.valid {
					if e != nil || caller != "assistant" {
						t.Fatal(caller, e)
					}
				} else if e == nil || caller != "" {
					t.Fatal("untrusted cluster key accepted")
				}
			} else {
				verifier, e := identity.NewUserVerifier(cache, opts(&now))
				if e != nil {
					t.Fatal(e)
				}
				id, e := verifier.VerifyUser(t.Context(), sign(t, tc.key, tc.algorithm, tc.jwk["kid"], baseClaims(now)))
				if tc.valid {
					if e != nil || id != "user-1" {
						t.Fatal(id, e)
					}
				} else if e == nil || id != "" {
					t.Fatal("untrusted user key accepted")
				}
			}
		})
	}
}

func TestIntegrationTLSJWTRejectionsAreObserved(t *testing.T) {
	now := time.Unix(1700000000, 0)
	pub, key := testKey(t)
	body := jwks(t, map[string]ed25519.PublicKey{"one": pub})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	defer server.Close()
	provider, err := identity.NewHTTPKeys(server.Client(), server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := identity.NewKeyCache(provider, func() time.Time { return now }, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	reg := prometheus.NewRegistry()
	observer, err := identity.NewMetrics(reg)
	if err != nil {
		t.Fatal(err)
	}
	o := opts(&now)
	o.Observer = observer
	v, err := identity.NewUserVerifier(cache, o)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*jwt.RegisteredClaims){func(c *jwt.RegisteredClaims) { c.Issuer = "foreign" }, func(c *jwt.RegisteredClaims) { c.Audience = jwt.ClaimStrings{"foreign"} }, func(c *jwt.RegisteredClaims) { c.ExpiresAt = jwt.NewNumericDate(now) }, func(c *jwt.RegisteredClaims) { c.Subject = "" }, func(c *jwt.RegisteredClaims) { c.IssuedAt = jwt.NewNumericDate(now.Add(time.Minute)) }} {
		claims := baseClaims(now)
		change(&claims)
		if id, err := v.VerifyUser(t.Context(), sign(t, key, jwt.SigningMethodEdDSA, "one", claims)); err == nil || id != "" {
			t.Fatal("invalid JWT admitted")
		}
	}
	otherPub, otherKey := testKey(t)
	_ = otherPub
	if _, err := v.VerifyUser(t.Context(), sign(t, otherKey, jwt.SigningMethodEdDSA, "one", baseClaims(now))); err == nil {
		t.Fatal("invalid signature accepted")
	}
	body = []byte("invalid")
	now = now.Add(2 * time.Minute)
	if _, err := v.VerifyUser(t.Context(), sign(t, key, jwt.SigningMethodEdDSA, "one", baseClaims(now))); err == nil {
		t.Fatal("stale key trusted")
	}
	families, err := reg.Gather()
	if err != nil || len(families) != 1 || len(families[0].Metric) < 4 {
		t.Fatal("bounded rejection reasons missing", err)
	}
}

func TestAPIJWKSEndpointTrustAndFailure(t *testing.T) {
	statusCode := http.StatusOK
	body := "{}"
	var requests atomic.Int32
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		if statusCode == http.StatusFound {
			w.Header().Set("Location", "/other")
		}
		w.WriteHeader(statusCode)
		_, _ = io.WriteString(w, body)
	}))
	defer endpoint.Close()
	for _, address := range []string{"http://example.invalid", "https://user:secret@example.invalid", endpoint.URL + "?secret=yes", endpoint.URL + "#secret", "://bad"} {
		if _, err := identity.NewHTTPKeys(endpoint.Client(), address, nil); err == nil {
			t.Fatal("unpinned endpoint accepted")
		}
	}
	if _, err := identity.NewHTTPKeys(nil, endpoint.URL, nil); err == nil {
		t.Fatal("missing TLS client accepted")
	}
	provider, err := identity.NewHTTPKeys(endpoint.Client(), endpoint.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []int{http.StatusFound, http.StatusForbidden, http.StatusInternalServerError} {
		statusCode = code
		before := requests.Load()
		if _, err := provider.JWKS(t.Context()); err == nil {
			t.Fatal("endpoint failure ignored")
		}
		if requests.Load() != before+1 {
			t.Fatal("redirect followed")
		}
	}
	statusCode = http.StatusOK
	body = strings.Repeat("x", 1<<20+1)
	if _, err := provider.JWKS(t.Context()); err == nil {
		t.Fatal("oversized JWKS accepted")
	}
	for _, source := range []tokenFunc{func(context.Context) (string, error) { return "", errors.New("secret credential") }, func(context.Context) (string, error) { return "bad\ntoken", nil }} {
		p, err := identity.NewHTTPKeys(endpoint.Client(), endpoint.URL, source)
		if err != nil {
			t.Fatal(err)
		}
		before := requests.Load()
		if _, err := p.JWKS(t.Context()); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("credential failure leaked", err)
		}
		if requests.Load() != before {
			t.Fatal("request sent without valid credential")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := provider.JWKS(ctx); err == nil {
		t.Fatal("cancelled request succeeded")
	}
}

func TestIntegrationStageFilesAndExpiry(t *testing.T) {
	now := time.Unix(1700000000, 0)
	pub, key := testKey(t)
	clock := func() time.Time { return now }
	path := writeKey(t, key)
	source, err := identity.NewStageSource("stage", identity.StageOptions{KeyFile: path, Caller: "assistant", Issuer: "stage", Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	verify, err := identity.NewStageVerifier("stage", identity.VerifyOptions{Issuer: "stage", Audience: "finassist-internal", Clock: clock}, map[string]ed25519.PublicKey{"assistant": pub})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := source.Token(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if second, err := source.Token(t.Context()); err != nil || second != raw {
		t.Fatal("stage token cache failed", err)
	}
	now = now.Add(time.Minute)
	if _, err := verify.VerifyService(t.Context(), raw); err == nil {
		t.Fatal("expired stage token trusted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := source.Token(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.NewStageSource("stage", identity.StageOptions{KeyFile: path, Caller: "assistant", Issuer: "stage", Clock: clock}); err == nil {
		t.Fatal("missing signing key accepted")
	}
	for _, data := range []string{"bad PEM", strings.Repeat("x", 8193), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("bad DER")}))} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := identity.NewStageSource("stage", identity.StageOptions{KeyFile: path, Caller: "assistant", Issuer: "stage", Clock: clock}); err == nil {
			t.Fatal("invalid signing file accepted")
		}
	}
	if _, err := identity.NewMetrics(nil); err == nil {
		t.Fatal("nil metric registerer accepted")
	}
}

func TestIntegrationRSAKeyCacheServesClusterButNotUserPolicy(t *testing.T) {
	now := time.Unix(1700000000, 0)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"keys": []map[string]string{{"kid": "cluster", "kty": "RSA", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	if err != nil {
		t.Fatal(err)
	}
	var fetches atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fetches.Add(1); _, _ = w.Write(body) }))
	defer server.Close()
	provider, err := identity.NewHTTPKeys(server.Client(), server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := identity.NewKeyCache(provider, func() time.Time { return now }, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	options := identity.VerifyOptions{Issuer: "cluster", Audience: "finassist-internal", Clock: func() time.Time { return now }}
	cluster, err := identity.NewKubernetesVerifier(cache, options, "finassist")
	if err != nil {
		t.Fatal(err)
	}
	user, err := identity.NewUserVerifier(cache, options)
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{"iss": "cluster", "aud": "finassist-internal", "sub": "system:serviceaccount:finassist:assistant", "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "kubernetes.io": map[string]any{"namespace": "finassist", "serviceaccount": map[string]any{"name": "assistant"}}}
	raw := sign(t, key, jwt.SigningMethodRS256, "cluster", claims)
	for range 2 {
		if caller, err := cluster.VerifyService(t.Context(), raw); err != nil || caller != "assistant" {
			t.Fatal(caller, err)
		}
	}
	if id, err := user.VerifyUser(t.Context(), raw); err == nil || id != "" {
		t.Fatal("cluster algorithm admitted as a user")
	}
	if fetches.Load() != 1 {
		t.Fatal("fresh RSA cache was not reused")
	}
}

func TestIntegrationJWKSProjectedCredentialOutage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api-token")
	if err := os.WriteFile(path, []byte("api-token"), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := identity.NewProjectedSource(path)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer api-token" {
			w.WriteHeader(401)
			return
		}
		_, _ = io.WriteString(w, `{"keys":[]}`)
	}))
	defer endpoint.Close()
	provider, err := identity.NewHTTPKeys(endpoint.Client(), endpoint.URL, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.JWKS(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.JWKS(t.Context()); err == nil || strings.Contains(err.Error(), path) {
		t.Fatal("missing projected credential leaked or ignored", err)
	}
	if err := os.WriteFile(path, []byte("invalid credential"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.JWKS(t.Context()); err == nil {
		t.Fatal("invalid projected credential admitted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := provider.JWKS(ctx); err == nil {
		t.Fatal("cancelled credential fetch succeeded")
	}
	if requests.Load() != 1 {
		t.Fatal("JWKS sent with missing or malformed credential")
	}
}
