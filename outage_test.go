package identity

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	analyticsv1 "github.com/fin-assist/contracts/gen/go/finassist/analytics/v1"
	userv1 "github.com/fin-assist/contracts/gen/go/finassist/user/v1"
	"github.com/fin-assist/contracts/gen/go/finerr"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// switchProvider serves keys or fails, counting network attempts.
type switchProvider struct {
	data  []byte
	fail  bool
	calls int
}

func (p *switchProvider) JWKS(context.Context) ([]byte, error) {
	p.calls++
	if p.fail {
		return nil, errors.New("secret transport detail")
	}
	return p.data, nil
}

func TestUnitKeyCacheSeparatesOutageFromUnknownKey(t *testing.T) {
	now := time.Unix(1700000000, 0)
	pub, _ := testKey(t)
	p := &switchProvider{data: jwks(t, map[string]ed25519.PublicKey{"one": pub}), fail: true}
	cache, err := NewKeyCache(p, func() time.Time { return now }, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Start during an outage: every lookup in the rate-limit window reports it.
	for range 3 {
		if _, err := cache.key(context.Background(), "one"); !errors.Is(err, errKeysUnavailable) {
			t.Fatal("startup outage not reported", err)
		}
	}
	if p.calls != 1 {
		t.Fatalf("outage refreshed %d times within a minute", p.calls)
	}
	now = now.Add(time.Minute)
	p.fail = false
	if _, err := cache.key(context.Background(), "one"); err != nil {
		t.Fatal(err)
	}
	// A fresh snapshot without the kid is a verdict, also while rate-limited.
	for range 3 {
		if _, err := cache.key(context.Background(), "forged"); !errors.Is(err, errUnknownKey) {
			t.Fatal("unknown kid not distinguished", err)
		}
	}
	if p.calls != 2 {
		t.Fatalf("calls=%d", p.calls)
	}
	// A failed refresh for an unknown kid is still judged by the fresh snapshot:
	// a random kid cannot turn a provider outage into UNAVAILABLE.
	now = now.Add(time.Minute)
	p.fail = true
	for _, kid := range []string{"rotated", "random", "one"} {
		k, err := cache.key(context.Background(), kid)
		if kid == "one" {
			if err != nil || k.algorithm != "EdDSA" {
				t.Fatal("known key lost after a failed refresh", err)
			}
			continue
		}
		if !errors.Is(err, errUnknownKey) {
			t.Fatal("unknown kid in a fresh snapshot not judged after a failed refresh", err)
		}
	}
	if p.calls != 3 {
		t.Fatalf("calls=%d, failed refresh not rate limited", p.calls)
	}
	// The snapshot expires during the outage: known keys are no longer trusted.
	now = now.Add(10 * time.Minute)
	if _, err := cache.key(context.Background(), "one"); !errors.Is(err, errKeysUnavailable) {
		t.Fatal("expired snapshot not reported as an outage", err)
	}
	// An invalid set is an outage as well, not a verdict on the token.
	now = now.Add(time.Minute)
	p.fail, p.data = false, []byte(`{"keys":[]}`)
	if _, err := cache.key(context.Background(), "one"); !errors.Is(err, errKeysUnavailable) {
		t.Fatal("invalid JWKS not reported as an outage", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cache.key(ctx, "one"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestUnitVerifiersReportOutageWithoutVerdict(t *testing.T) {
	now := time.Unix(1700000000, 0)
	pub, key := testKey(t)
	p := &switchProvider{data: jwks(t, map[string]ed25519.PublicKey{"one": pub}), fail: true}
	cache, _ := NewKeyCache(p, func() time.Time { return now }, 10*time.Minute)
	seen := &observer{}
	o := opts(&now)
	o.Observer = seen
	users, err := NewUserVerifier(cache, o)
	if err != nil {
		t.Fatal(err)
	}
	raw := sign(t, key, jwt.SigningMethodEdDSA, "one", baseClaims(now))
	id, err := users.VerifyUser(context.Background(), raw)
	if status.Code(err) != codes.Unavailable || id != "" || len(status.Convert(err).Details()) != 0 || status.Convert(err).Message() != "" {
		t.Fatal("outage is not a bare UNAVAILABLE", err)
	}
	if _, ok := finerr.ToREST(err); ok {
		t.Fatal("outage mapped to a client-facing reason")
	}
	now = now.Add(time.Minute)
	p.fail = false
	raw = sign(t, key, jwt.SigningMethodEdDSA, "one", baseClaims(now))
	if id, err := users.VerifyUser(context.Background(), raw); err != nil || id != "user-1" {
		t.Fatal(id, err)
	}
	if rest, ok := finerr.ToREST(func() error {
		_, e := users.VerifyUser(context.Background(), sign(t, key, jwt.SigningMethodEdDSA, "forged", baseClaims(now)))
		return e
	}()); !ok || rest.Code != "INVALID_TOKEN" {
		t.Fatal("unknown kid in a fresh snapshot is not INVALID_TOKEN")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := users.VerifyUser(cancelled, raw); status.Code(err) != codes.Canceled {
		t.Fatal(err)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer stop()
	if _, err := users.VerifyUser(expired, raw); status.Code(err) != codes.DeadlineExceeded {
		t.Fatal(err)
	}
	if want := []string{"user:key_unavailable", "user:unknown_key"}; !slices.Equal(seen.reasons, want) {
		t.Fatalf("reasons=%v want=%v", seen.reasons, want)
	}

	// Service verifiers: an outage is a bare UNAVAILABLE, a verdict stays internal.
	p.fail = true
	now = now.Add(11 * time.Minute)
	raw = sign(t, key, jwt.SigningMethodEdDSA, "one", baseClaims(now))
	services, err := NewKubernetesVerifier(cache, VerifyOptions{Issuer: "user", Audience: "finassist-internal", Clock: func() time.Time { return now }}, "finassist")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := services.VerifyService(context.Background(), raw); status.Code(err) != codes.Unavailable {
		t.Fatal("service key outage not UNAVAILABLE", err)
	}
	if _, err := services.VerifyService(context.Background(), "bad"); err == nil || status.Code(err) != codes.Unknown {
		t.Fatal("malformed service token not an internal verdict", err)
	}
	stage, err := NewStageVerifier("stage", VerifyOptions{Issuer: "stage", Audience: "finassist-internal", Clock: func() time.Time { return now }}, map[string]ed25519.PublicKey{"bank-bff": pub})
	if err != nil {
		t.Fatal(err)
	}
	c := baseClaims(now)
	c.Issuer, c.Audience, c.Subject = "stage", jwt.ClaimStrings{"finassist-internal"}, "assistant"
	if _, err := stage.VerifyService(context.Background(), sign(t, key, jwt.SigningMethodEdDSA, "assistant", c)); err == nil || status.Code(err) != codes.Unknown {
		t.Fatal("unknown stage key not an internal verdict", err)
	}
}

func TestUnitServerAndHTTPPassUnjudgedStatus(t *testing.T) {
	outage := status.Error(codes.Unavailable, "secret detail")
	for _, tc := range []struct {
		name     string
		services ServiceChecker
		users    UserChecker
		code     codes.Code
		reason   string
	}{
		{"service keys unavailable", serviceFunc(func(context.Context, string) (string, error) { return "", outage }), goodUser(), codes.Unavailable, ""},
		{"service check cancelled", serviceFunc(func(context.Context, string) (string, error) {
			return "", status.Error(codes.Canceled, "secret detail")
		}), goodUser(), codes.Canceled, ""},
		{"service verdict", serviceFunc(func(context.Context, string) (string, error) {
			return "", status.Error(codes.Internal, "secret detail")
		}), goodUser(), codes.Unauthenticated, ""},
		{"user keys unavailable", goodService(), userFunc(func(context.Context, string) (string, error) { return "", outage }), codes.Unavailable, ""},
		{"user check deadline", goodService(), userFunc(func(context.Context, string) (string, error) {
			return "", status.Error(codes.DeadlineExceeded, "secret detail")
		}), codes.DeadlineExceeded, ""},
		{"user verdict", goodService(), userFunc(func(context.Context, string) (string, error) { return "", errors.New("secret detail") }), codes.Unauthenticated, "INVALID_TOKEN"},
		{"user empty subject", goodService(), userFunc(func(context.Context, string) (string, error) { return " ", nil }), codes.Unauthenticated, "INVALID_TOKEN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewServer(AccessTable{"/test.Service/Method": {"bank-bff": User}}, tc.services, tc.users, nil)
			if err != nil {
				t.Fatal(err)
			}
			called := false
			_, err = s.Unary()(incoming("bank-bff", "access"), &analyticsv1.GetAnalyticsRequest{}, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}, func(context.Context, any) (any, error) {
				called = true
				return nil, nil
			})
			assertRefusal(t, err, tc.code, tc.reason)
			if called {
				t.Fatal("handler ran")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		users  UserChecker
		code   codes.Code
		reason string
	}{
		{"keys unavailable", userFunc(func(context.Context, string) (string, error) { return "", outage }), codes.Unavailable, ""},
		{"verdict", userFunc(func(context.Context, string) (string, error) { return "", errors.New("secret detail") }), codes.Unauthenticated, "INVALID_TOKEN"},
		{"empty subject", userFunc(func(context.Context, string) (string, error) { return "", nil }), codes.Unauthenticated, "INVALID_TOKEN"},
	} {
		t.Run("HTTP "+tc.name, func(t *testing.T) {
			var got error
			m, err := NewHTTP(tc.users, func(w http.ResponseWriter, _ *http.Request, e error) { got = e; w.WriteHeader(599) })
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodGet, "/v1/analytics", nil)
			r.Header.Set("Authorization", "Bearer access")
			m.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("handler ran") })).ServeHTTP(httptest.NewRecorder(), r)
			assertRefusal(t, got, tc.code, tc.reason)
		})
	}
}

func assertRefusal(t *testing.T, err error, code codes.Code, reason string) {
	t.Helper()
	if status.Code(err) != code || strings.Contains(err.Error(), "secret") {
		t.Fatalf("code=%v want=%v err=%v", status.Code(err), code, err)
	}
	rest, ok := finerr.ToREST(err)
	if reason == "" {
		if ok || len(status.Convert(err).Details()) != 0 {
			t.Fatal("unjudged refusal carries details", err)
		}
		return
	}
	if !ok || rest.Code != reason {
		t.Fatal("wrong reason", err)
	}
}

// flakyKeysAPI plays the user service: GetSigningKeys fails while down is set.
type flakyKeysAPI struct {
	userv1.UnimplementedUserInternalServiceServer
	body string
	down atomic.Bool
}

func (k *flakyKeysAPI) GetSigningKeys(context.Context, *userv1.GetSigningKeysRequest) (*userv1.GetSigningKeysResponse, error) {
	if k.down.Load() {
		return nil, status.Error(codes.Unavailable, "user is restarting")
	}
	return &userv1.GetSigningKeysResponse{JwksJson: k.body}, nil
}

func TestIntegrationUsageKeyOutageThroughInterceptors(t *testing.T) {
	now := time.Unix(1700000000, 0)
	clock := func() time.Time { return now }
	userPub, userKey := testKey(t)
	svcPub, svcKey := testKey(t)
	clusterPub, clusterKey := testKey(t)
	source, err := NewStageSource("stage", StageOptions{KeyFile: writeKey(t, svcKey), Caller: "bank-bff", Issuer: "stage", Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	stage, err := NewStageVerifier("stage", VerifyOptions{Issuer: "stage", Audience: "finassist-internal", Clock: clock}, map[string]ed25519.PublicKey{"bank-bff": svcPub})
	if err != nil {
		t.Fatal(err)
	}
	// The user service publishes its keys over the authenticated GetSigningKeys RPC.
	keysServer, err := NewServer(AccessTable{userv1.UserInternalService_GetSigningKeys_FullMethodName: {"bank-bff": NoUser}}, stage, goodUser(), nil)
	if err != nil {
		t.Fatal(err)
	}
	keysGRPC := grpc.NewServer(grpc.ChainUnaryInterceptor(keysServer.Unary()))
	keys := &flakyKeysAPI{body: string(jwks(t, map[string]ed25519.PublicKey{"one": userPub}))}
	keys.down.Store(true)
	userv1.RegisterUserInternalServiceServer(keysGRPC, keys)
	cache, err := NewKeyCache(UserKeys{Client: userv1.NewUserInternalServiceClient(dialServer(t, keysGRPC, source))}, clock, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	seen := &observer{}
	users, err := NewUserVerifier(cache, VerifyOptions{Issuer: "user", Audience: "finassist", Clock: clock, Observer: seen})
	if err != nil {
		t.Fatal(err)
	}
	// Kubernetes keys come from a TLS API-server endpoint that is down as well.
	clusterDown := new(atomic.Bool)
	clusterDown.Store(true)
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if clusterDown.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(jwks(t, map[string]ed25519.PublicKey{"cluster": clusterPub}))
	}))
	defer endpoint.Close()
	provider, err := NewHTTPKeys(endpoint.Client(), endpoint.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	clusterCache, err := NewKeyCache(provider, clock, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	kubernetes, err := NewKubernetesVerifier(clusterCache, VerifyOptions{Issuer: "cluster", Audience: "finassist-internal", Clock: clock}, "finassist")
	if err != nil {
		t.Fatal(err)
	}
	method := analyticsv1.AnalyticsService_GetAnalytics_FullMethodName
	userAccess, err := NewServer(AccessTable{method: {"bank-bff": User}}, stage, users, nil)
	if err != nil {
		t.Fatal(err)
	}
	systemAccess, err := NewServer(AccessTable{method: {"assistant": System}}, kubernetes, users, nil)
	if err != nil {
		t.Fatal(err)
	}
	userAPI, systemAPI := new(analyticsAPI), new(analyticsAPI)
	userGRPC := grpc.NewServer(grpc.ChainUnaryInterceptor(userAccess.Unary()))
	analyticsv1.RegisterAnalyticsServiceServer(userGRPC, userAPI)
	systemGRPC := grpc.NewServer(grpc.ChainUnaryInterceptor(systemAccess.Unary()))
	analyticsv1.RegisterAnalyticsServiceServer(systemGRPC, systemAPI)
	userClient := analyticsv1.NewAnalyticsServiceClient(dialServer(t, userGRPC, source))
	projected := tokenFunc(func(context.Context) (string, error) {
		claims := jwt.MapClaims{"iss": "cluster", "aud": "finassist-internal", "sub": "system:serviceaccount:finassist:assistant", "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "kubernetes.io": map[string]any{"namespace": "finassist", "serviceaccount": map[string]any{"name": "assistant"}}}
		return sign(t, clusterKey, jwt.SigningMethodEdDSA, "cluster", claims), nil
	})
	systemClient := analyticsv1.NewAnalyticsServiceClient(dialServer(t, systemGRPC, projected))
	var written error
	edge, err := NewHTTP(users, func(w http.ResponseWriter, _ *http.Request, e error) { written = e; w.WriteHeader(599) })
	if err != nil {
		t.Fatal(err)
	}
	edgeHandler := edge.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	call := func() (int, error, error) {
		token := sign(t, userKey, jwt.SigningMethodEdDSA, "one", baseClaims(now))
		ctx := context.WithValue(context.Background(), identityKey{}, principal{model: User, userID: "user-1", token: token})
		_, userErr := userClient.GetAnalytics(ctx, &analyticsv1.GetAnalyticsRequest{})
		_, systemErr := systemClient.GetAnalytics(context.Background(), &analyticsv1.GetAnalyticsRequest{UserId: proto.String("user-1")})
		r := httptest.NewRequest(http.MethodGet, "/v1/analytics", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		written = nil
		edgeHandler.ServeHTTP(w, r)
		return w.Code, userErr, systemErr
	}
	code, userErr, systemErr := call()
	assertRefusal(t, userErr, codes.Unavailable, "")
	assertRefusal(t, systemErr, codes.Unavailable, "")
	if code != 599 {
		t.Fatal("edge handler ran during the key outage", code)
	}
	assertRefusal(t, written, codes.Unavailable, "")
	if userAPI.calls.Load() != 0 || systemAPI.calls.Load() != 0 {
		t.Fatal("handler ran during the key outage")
	}
	now = now.Add(time.Minute)
	keys.down.Store(false)
	clusterDown.Store(false)
	code, userErr, systemErr = call()
	if userErr != nil || systemErr != nil || code != http.StatusNoContent {
		t.Fatal("recovered keys refused", userErr, systemErr, code)
	}
	if !slices.Contains(seen.reasons, "user:key_unavailable") || slices.Contains(seen.reasons, "user:invalid") {
		t.Fatalf("reasons=%v", seen.reasons)
	}
}

// A failed proactive refresh inside the minute limit must not turn an unknown kid
// into an outage while the snapshot is fresh: the stored snapshot judges it.
func TestUnitFailedProactiveRefreshKeepsUnknownKidVerdict(t *testing.T) {
	now := time.Unix(1700000000, 0)
	pub, _ := testKey(t)
	p := &switchProvider{data: jwks(t, map[string]ed25519.PublicKey{"one": pub})}
	cache, err := NewKeyCache(p, func() time.Time { return now }, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	cache.refreshIfDue(context.Background())
	now = now.Add(5 * time.Minute)
	p.fail = true
	cache.refreshIfDue(context.Background())
	if p.calls != 2 {
		t.Fatalf("proactive refresh at half the interval did not run: calls=%d", p.calls)
	}
	now = now.Add(30 * time.Second)
	if _, err := cache.key(context.Background(), "unknown"); !errors.Is(err, errUnknownKey) {
		t.Fatal("unknown kid after a failed proactive refresh is not a verdict", err)
	}
	if k, err := cache.key(context.Background(), "one"); err != nil || k.algorithm != "EdDSA" {
		t.Fatal("known key lost after a failed proactive refresh", err)
	}
	if p.calls != 2 {
		t.Fatalf("unknown kid bypassed the minute limit: calls=%d", p.calls)
	}
}
