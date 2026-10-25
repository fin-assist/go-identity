package identity_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	analyticsv1 "github.com/fin-assist/contracts/gen/go/finassist/analytics/v1"
	userv1 "github.com/fin-assist/contracts/gen/go/finassist/user/v1"
	"github.com/fin-assist/contracts/gen/go/finerr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"

	"github.com/fin-assist/go-identity"
)

// metricValues returns the values of one metric family by "kind/reason".
func metricValues(t *testing.T, reg prometheus.Gatherer, name string) map[string]float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.Metric {
			labels := map[string]string{}
			for _, l := range m.Label {
				labels[l.GetName()] = l.GetValue()
			}
			value := m.GetGauge().GetValue()
			if m.GetCounter() != nil {
				value = m.GetCounter().GetValue()
			}
			got[labels["kind"]+"/"+labels["reason"]] = value
		}
	}
	return got
}

func coordinate(v *big.Int, size int) string {
	return base64.RawURLEncoding.EncodeToString(v.FillBytes(make([]byte, size)))
}

// TestIntegrationKubernetesMixedJWKSOverTLS serves the JWKS a Kubernetes API
// server publishes after adding an EC P-384 ServiceAccount key next to an RSA
// one: go-jose JSON with use=sig, alg RS256 and ES384. Before FIN-311 the whole
// set was rejected and the supported RSA token failed too.
func TestIntegrationKubernetesMixedJWKSOverTLS(t *testing.T) {
	now := time.Unix(1700000000, 0)
	clock := func() time.Time { return now }
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	body := `{"keys":[` +
		`{"use":"sig","kty":"RSA","kid":"rsa-kid-sha256","alg":"RS256","n":"` + enc(rsaKey.N.Bytes()) + `","e":"AQAB"},` +
		`{"use":"sig","kty":"EC","kid":"ec-kid-sha256","crv":"P-384","alg":"ES384","x":"` + coordinate(p384.X, 48) + `","y":"` + coordinate(p384.Y, 48) + `"}]}`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	provider, err := identity.NewHTTPKeys(server.Client(), server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	reg := prometheus.NewRegistry()
	metrics, err := identity.NewMetrics(reg)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := identity.NewObservedKeyCache(provider, clock, time.Hour, "service", metrics)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := identity.NewKubernetesVerifier(cache, identity.VerifyOptions{Issuer: "https://kubernetes.default.svc.cluster.local", Audience: "finassist-internal", Clock: clock, Observer: metrics}, "finassist")
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{"iss": "https://kubernetes.default.svc.cluster.local", "aud": "finassist-internal", "sub": "system:serviceaccount:finassist:assistant", "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "kubernetes.io": map[string]any{"namespace": "finassist", "serviceaccount": map[string]any{"name": "assistant"}}}
	if caller, err := verifier.VerifyService(t.Context(), sign(t, rsaKey, jwt.SigningMethodRS256, "rsa-kid-sha256", claims)); err != nil || caller != "assistant" {
		t.Fatal("supported RSA key of a mixed Kubernetes set rejected", caller, err)
	}
	skipped := metricValues(t, reg, "finassist_identity_jwks_skipped_keys")
	if len(skipped) != 6 || skipped["service/crv"] != 1 || skipped["service/kty"] != 0 || skipped["service/size"] != 0 {
		t.Fatal("skipped keys gauge", skipped)
	}
	before := metricValues(t, reg, "finassist_identity_rejected_total")
	if caller, err := verifier.VerifyService(t.Context(), sign(t, p384, jwt.SigningMethodES384, "ec-kid-sha256", claims)); err == nil || caller != "" {
		t.Fatal("token of a skipped key accepted")
	}
	skippedKid := diff(before, metricValues(t, reg, "finassist_identity_rejected_total"))
	before = metricValues(t, reg, "finassist_identity_rejected_total")
	if _, err := verifier.VerifyService(t.Context(), sign(t, p384, jwt.SigningMethodES384, "absent-kid", claims)); err == nil {
		t.Fatal("token of an absent key accepted")
	}
	absentKid := diff(before, metricValues(t, reg, "finassist_identity_rejected_total"))
	if len(skippedKid) != 1 || len(absentKid) != 1 || skippedKid[0] != absentKid[0] {
		t.Fatal("skipped kid outcome differs from unknown kid", skippedKid, absentKid)
	}
}

// diff returns the series whose value grew between two snapshots.
func diff(before, after map[string]float64) []string {
	var grown []string
	for series, value := range after {
		if value > before[series] {
			grown = append(grown, series)
		}
	}
	return grown
}

// lateUsers lets the test server check users with a verifier built after it.
type lateUsers struct{ v *identity.UserVerifier }

func (l *lateUsers) VerifyUser(ctx context.Context, token string) (string, error) {
	if l.v == nil {
		return "", errors.New("verifier not wired")
	}
	return l.v.VerifyUser(ctx, token)
}

// TestAPIUserMixedJWKSThroughConsumerWiring follows README «Внедрение»: user keys
// come from GetSigningKeys over an authenticated generated client, the HTTP
// middleware verifies the access token and the forwarded user reaches a handler.
// A user JWKS with an encryption key and an X25519 key keeps verifying its
// signing keys; a token naming a skipped key is INVALID_TOKEN and never reaches it.
func TestAPIUserMixedJWKSThroughConsumerWiring(t *testing.T) {
	now := time.Unix(1700000000, 0)
	clock := func() time.Time { return now }
	userPub, userKey := testKey(t)
	encPub, encKey := testKey(t)
	svcPub, svcKey := testKey(t)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	body := `{"keys":[` +
		`{"kid":"one","kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","x":"` + enc(userPub) + `"},` +
		`{"kid":"ec","kty":"EC","crv":"P-256","alg":"ES256","x":"` + coordinate(ec.X, 32) + `","y":"` + coordinate(ec.Y, 32) + `"},` +
		`{"kid":"enc","kty":"OKP","crv":"Ed25519","use":"enc","x":"` + enc(encPub) + `"},` +
		`{"kid":"agreement","kty":"OKP","crv":"X25519","x":"` + enc(make([]byte, 32)) + `"}]}`
	source, err := identity.NewStageSource("stage", identity.StageOptions{KeyFile: writeKey(t, svcKey), Caller: "bank-bff", Issuer: "stage", Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	services, err := identity.NewStageVerifier("stage", identity.VerifyOptions{Issuer: "stage", Audience: "finassist-internal", Clock: clock}, map[string]ed25519.PublicKey{"bank-bff": svcPub})
	if err != nil {
		t.Fatal(err)
	}
	users := &lateUsers{}
	method := analyticsv1.AnalyticsService_GetAnalytics_FullMethodName
	access, err := identity.NewServer(identity.AccessTable{method: {"bank-bff": identity.User}, userv1.UserInternalService_GetSigningKeys_FullMethodName: {"bank-bff": identity.NoUser}}, services, users, nil)
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := grpc.NewServer(grpc.ChainUnaryInterceptor(access.Unary()))
	api := new(analyticsAPI)
	analyticsv1.RegisterAnalyticsServiceServer(grpcServer, api)
	keys := &keysAPI{body: body}
	userv1.RegisterUserInternalServiceServer(grpcServer, keys)
	conn := dialServer(t, grpcServer, source)
	reg := prometheus.NewRegistry()
	metrics, err := identity.NewMetrics(reg)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := identity.NewObservedKeyCache(identity.UserKeys{Client: userv1.NewUserInternalServiceClient(conn)}, clock, 10*time.Minute, "user", metrics)
	if err != nil {
		t.Fatal(err)
	}
	o := opts(&now)
	o.Observer = metrics
	users.v, err = identity.NewUserVerifier(cache, o)
	if err != nil {
		t.Fatal(err)
	}
	client := analyticsv1.NewAnalyticsServiceClient(conn)
	middleware, err := identity.NewHTTP(users.v, func(w http.ResponseWriter, _ *http.Request, e error) {
		rest, ok := finerr.ToREST(e)
		if !ok || rest.Code != "INVALID_TOKEN" {
			t.Error(e)
		}
		w.WriteHeader(rest.Spec.HTTPStatus)
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := client.GetAnalytics(r.Context(), &analyticsv1.GetAnalyticsRequest{}); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	call := func(raw string) int {
		r := httptest.NewRequest(http.MethodGet, "/v1/analytics", nil)
		r.Header.Set("Authorization", "Bearer "+raw)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	for _, tc := range []struct {
		name string
		raw  string
		want int
	}{
		{"Ed25519 signing key", sign(t, userKey, jwt.SigningMethodEdDSA, "one", baseClaims(now)), http.StatusNoContent},
		{"ES256 signing key", sign(t, ec, jwt.SigningMethodES256, "ec", baseClaims(now)), http.StatusNoContent},
		{"skipped encryption key", sign(t, encKey, jwt.SigningMethodEdDSA, "enc", baseClaims(now)), http.StatusUnauthorized},
		{"skipped X25519 key", sign(t, userKey, jwt.SigningMethodEdDSA, "agreement", baseClaims(now)), http.StatusUnauthorized},
		{"absent key", sign(t, userKey, jwt.SigningMethodEdDSA, "absent", baseClaims(now)), http.StatusUnauthorized},
	} {
		if got := call(tc.raw); got != tc.want {
			t.Fatalf("%s: status=%d want=%d", tc.name, got, tc.want)
		}
	}
	if api.calls.Load() != 2 {
		t.Fatal("token of a skipped key reached the handler", api.calls.Load())
	}
	skipped := metricValues(t, reg, "finassist_identity_jwks_skipped_keys")
	if skipped["user/use"] != 1 || skipped["user/crv"] != 1 || skipped["user/alg"] != 0 {
		t.Fatal("skipped keys gauge", skipped)
	}
	// Rotation drops the unsupported keys: the next snapshot resets the gauge.
	keys.body = `{"keys":[{"kid":"one","kty":"OKP","crv":"Ed25519","alg":"EdDSA","x":"` + enc(userPub) + `"}]}`
	now = now.Add(10 * time.Minute)
	if got := call(sign(t, userKey, jwt.SigningMethodEdDSA, "one", baseClaims(now))); got != http.StatusNoContent {
		t.Fatal("rotated snapshot", got)
	}
	for series, value := range metricValues(t, reg, "finassist_identity_jwks_skipped_keys") {
		if value != 0 {
			t.Fatal("gauge not reset after rotation", series, value)
		}
	}
	for _, bad := range []string{"", "access"} {
		if _, err := identity.NewObservedKeyCache(identity.UserKeys{}, clock, 10*time.Minute, bad, metrics); err == nil {
			t.Fatal("invalid kind accepted", bad)
		}
	}
	if _, err := identity.NewObservedKeyCache(identity.UserKeys{}, clock, 10*time.Minute, "user", nil); err == nil {
		t.Fatal("missing observer accepted")
	}
}
