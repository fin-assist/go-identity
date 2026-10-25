package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func jwkSet(t *testing.T, keys ...map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// policyKeys holds real key material for the JWKS policy tests.
type policyKeys struct {
	ed      map[string]any // supported Ed25519 key "good"
	p256    *ecdsa.PrivateKey
	p384    *ecdsa.PrivateKey
	rsa2048 *rsa.PrivateKey
}

func newPolicyKeys(t *testing.T) policyKeys {
	t.Helper()
	pub, _ := testKey(t)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return policyKeys{ed: map[string]any{"kid": "good", "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "x": b64(pub)}, p256: p256, p384: p384, rsa2048: r}
}

func ecJWK(kid string, k *ecdsa.PrivateKey, crv, alg string) map[string]any {
	size := (k.Curve.Params().BitSize + 7) / 8
	return map[string]any{"use": "sig", "kty": "EC", "kid": kid, "crv": crv, "alg": alg, "x": b64(k.X.FillBytes(make([]byte, size))), "y": b64(k.Y.FillBytes(make([]byte, size)))}
}

func rsaJWK(kid string, n *big.Int, e int, alg string) map[string]any {
	j := map[string]any{"use": "sig", "kty": "RSA", "kid": kid, "n": b64(n.Bytes()), "e": b64(big.NewInt(int64(e)).Bytes())}
	if alg != "" {
		j["alg"] = alg
	}
	return j
}

// oversizedModulus is an odd 4097-bit number: parsing never checks primality.
func oversizedModulus() *big.Int {
	n := new(big.Int).Lsh(big.NewInt(1), 4096)
	return n.Add(n, big.NewInt(1))
}

func with(base map[string]any, changes map[string]any) map[string]any {
	j := map[string]any{}
	for k, v := range base {
		j[k] = v
	}
	for k, v := range changes {
		if v == nil {
			delete(j, k)
		} else {
			j[k] = v
		}
	}
	return j
}

func TestUnitParseJWKSSkipsUnsupportedKeys(t *testing.T) {
	k := newPolicyKeys(t)
	cases := []struct {
		name, reason string
		jwk          map[string]any
	}{
		{"unknown kty", skipKty, map[string]any{"kid": "s", "kty": "oct", "k": "c2VjcmV0"}},
		{"EC P-384 ES384 (Kubernetes)", skipCrv, ecJWK("s", k.p384, "P-384", "ES384")},
		{"OKP X25519", skipCrv, map[string]any{"kid": "s", "kty": "OKP", "crv": "X25519", "x": "not-decoded"}},
		{"EC P-256 with ES384", skipAlg, ecJWK("s", k.p256, "P-256", "ES384")},
		{"RSA PS256", skipAlg, rsaJWK("s", k.rsa2048.N, k.rsa2048.E, "PS256")},
		{"weak RSA PS256 is unsupported, not broken", skipAlg, rsaJWK("s", big.NewInt(0xffff1), 3, "PS256")},
		{"OKP with Ed448 alg", skipAlg, with(k.ed, map[string]any{"kid": "s", "alg": "Ed448"})},
		{"encryption key", skipUse, with(k.ed, map[string]any{"kid": "s", "use": "enc"})},
		{"encryption key of unknown type", skipUse, map[string]any{"kid": "s", "kty": "oct", "use": "enc"}},
		{"key_ops without verify", skipKeyOps, with(k.ed, map[string]any{"kid": "s", "key_ops": []string{"sign", "encrypt"}})},
		{"RSA longer than 4096 bits", skipSize, rsaJWK("s", oversizedModulus(), 65537, "RS256")},
		{"RSA longer than 4096 bits without alg", skipSize, rsaJWK("s", oversizedModulus(), 65537, "")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseJWKS(jwkSet(t, tc.jwk, k.ed))
			if err != nil {
				t.Fatal("whole set rejected for one unsupported key:", err)
			}
			if _, ok := got.byKID["s"]; ok {
				t.Fatal("unsupported key kept")
			}
			if _, ok := got.byKID["good"]; !ok || len(got.byKID) != 1 {
				t.Fatal("supported key lost", got.byKID)
			}
			if len(got.skipped) != 1 || got.skipped[tc.reason] != 1 {
				t.Fatal("skip reason", got.skipped)
			}
		})
	}
	t.Run("counts per reason in one set", func(t *testing.T) {
		got, err := parseJWKS(jwkSet(t, k.ed, ecJWK("a", k.p384, "P-384", "ES384"), ecJWK("b", k.p384, "P-521", "ES512"), rsaJWK("c", k.rsa2048.N, k.rsa2048.E, "RS256"), with(k.ed, map[string]any{"kid": "d", "use": "enc"})))
		if err != nil {
			t.Fatal(err)
		}
		if len(got.byKID) != 2 || got.skipped[skipCrv] != 2 || got.skipped[skipUse] != 1 || len(got.skipped) != 2 {
			t.Fatal(got.byKID, got.skipped)
		}
	})
	t.Run("supported optional members", func(t *testing.T) {
		got, err := parseJWKS(jwkSet(t, with(k.ed, map[string]any{"use": "sig", "key_ops": []string{"sign", "verify"}, "alg": nil})))
		if err != nil || len(got.byKID) != 1 || len(got.skipped) != 0 {
			t.Fatal(got, err)
		}
	})
}

func TestUnitParseJWKSRejectsBrokenSets(t *testing.T) {
	k := newPolicyKeys(t)
	good := string(jwkSet(t, k.ed))
	skipped := ecJWK("p384", k.p384, "P-384", "ES384")
	many := []map[string]any{k.ed}
	for i := range 64 {
		many = append(many, with(skipped, map[string]any{"kid": "s" + strconv.Itoa(i)}))
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	bodies := map[string]string{
		"empty":                           "",
		"not JSON":                        "not json",
		"trailing data":                   good + " x",
		"second JSON value":               good + "{}",
		"keys not a list":                 `{"keys":{}}`,
		"wrong member type":               `{"keys":[{"kid":"k","kty":5}]}`,
		"no keys":                         `{"keys":[]}`,
		"only unsupported keys":           string(jwkSet(t, skipped, with(k.ed, map[string]any{"kid": "e", "use": "enc"}))),
		"more than 64 keys":               string(jwkSet(t, many...)),
		"larger than 1 MiB":               good + strings.Repeat(" ", maxJWKS),
		"duplicate kept kid":              string(jwkSet(t, k.ed, k.ed)),
		"duplicate kid skipped then kept": string(jwkSet(t, with(skipped, map[string]any{"kid": "good"}), k.ed)),
		"duplicate kid kept then skipped": string(jwkSet(t, k.ed, with(skipped, map[string]any{"kid": "good"}))),
		"duplicate kid of skipped keys":   string(jwkSet(t, k.ed, skipped, skipped)),
		"skipped key without kid":         string(jwkSet(t, k.ed, with(skipped, map[string]any{"kid": nil}))),
		"oversized kid":                   string(jwkSet(t, k.ed, with(skipped, map[string]any{"kid": strings.Repeat("k", 257)}))),
		"bad Ed25519 base64":              string(jwkSet(t, k.ed, with(k.ed, map[string]any{"kid": "b", "x": "bad!"}))),
		"short Ed25519 key":               string(jwkSet(t, k.ed, with(k.ed, map[string]any{"kid": "b", "x": b64(make([]byte, 31))}))),
		"bad EC base64":                   string(jwkSet(t, k.ed, with(ecJWK("b", k.p256, "P-256", "ES256"), map[string]any{"y": "bad!"}))),
		"EC point not on curve":           string(jwkSet(t, k.ed, with(ecJWK("b", k.p256, "P-256", "ES256"), map[string]any{"x": b64(make([]byte, 32)), "y": b64(make([]byte, 32))}))),
		"bad RSA modulus base64":          string(jwkSet(t, k.ed, with(rsaJWK("b", k.rsa2048.N, 65537, "RS256"), map[string]any{"n": "bad!"}))),
		"bad RSA exponent":                string(jwkSet(t, k.ed, rsaJWK("b", k.rsa2048.N, 2, "RS256"))),
		"weak RSA RS256":                  string(jwkSet(t, k.ed, rsaJWK("b", weak.N, weak.E, "RS256"))),
		"weak RSA without alg":            string(jwkSet(t, k.ed, rsaJWK("b", weak.N, weak.E, ""))),
		"oversized RSA with bad exponent": string(jwkSet(t, k.ed, rsaJWK("b", oversizedModulus(), 4, "RS256"))),
		"oversized RSA exponent encoding": string(jwkSet(t, k.ed, with(rsaJWK("b", k.rsa2048.N, 65537, "RS256"), map[string]any{"e": b64([]byte{1, 0, 0, 0, 1})}))),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			if _, err := parseJWKS([]byte(body)); err == nil {
				t.Fatal("broken set accepted")
			}
		})
	}
}

type skipRecord struct {
	kind, reason string
	count        int
}

type skipObserver struct {
	mu      sync.Mutex
	records []skipRecord
}

func (o *skipObserver) SkippedKeys(kind, reason string, count int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.records = append(o.records, skipRecord{kind, reason, count})
}

func (o *skipObserver) take() map[string]int {
	o.mu.Lock()
	defer o.mu.Unlock()
	got := map[string]int{}
	for _, r := range o.records {
		if r.kind != "service" {
			got["wrong kind "+r.kind]++
		}
		got[r.reason] = r.count
	}
	o.records = nil
	return got
}

func TestUnitKeyCacheReportsSkippedKeysAndTreatsThemAsUnknown(t *testing.T) {
	k := newPolicyKeys(t)
	now := time.Unix(1700000000, 0)
	clock := func() time.Time { return now }
	body := jwkSet(t, k.ed, rsaJWK("rsa", k.rsa2048.N, k.rsa2048.E, "RS256"), ecJWK("p384", k.p384, "P-384", "ES384"), rsaJWK("big", oversizedModulus(), 65537, "RS256"))
	var fail bool
	provider := providerFunc(func(context.Context) ([]byte, error) {
		if fail {
			return nil, errors.New("down")
		}
		return body, nil
	})
	for _, bad := range []struct {
		kind     string
		observer KeyObserver
	}{{"access", &skipObserver{}}, {"", &skipObserver{}}, {"service", nil}} {
		if _, err := NewObservedKeyCache(provider, clock, time.Hour, bad.kind, bad.observer); err == nil {
			t.Fatal("invalid observer options accepted", bad.kind)
		}
	}
	if _, err := NewObservedKeyCache(provider, nil, time.Hour, "service", &skipObserver{}); err == nil {
		t.Fatal("invalid base options accepted")
	}
	observer := &skipObserver{}
	cache, err := NewObservedKeyCache(provider, clock, time.Hour, "service", observer)
	if err != nil {
		t.Fatal(err)
	}
	rejects := &observerRecorder{}
	v, err := NewKubernetesVerifier(cache, VerifyOptions{Issuer: "cluster", Audience: "finassist-internal", Clock: clock, Observer: rejects}, "finassist")
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{"iss": "cluster", "aud": "finassist-internal", "sub": "system:serviceaccount:finassist:assistant", "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "kubernetes.io": map[string]any{"namespace": "finassist", "serviceaccount": map[string]any{"name": "assistant"}}}
	if caller, err := v.VerifyService(context.Background(), sign(t, k.rsa2048, jwt.SigningMethodRS256, "rsa", claims)); err != nil || caller != "assistant" {
		t.Fatal("supported key of a mixed set rejected", caller, err)
	}
	want := map[string]int{skipKty: 0, skipCrv: 1, skipAlg: 0, skipUse: 0, skipKeyOps: 0, skipSize: 1}
	if got := observer.take(); len(got) != len(want) || got[skipCrv] != 1 || got[skipSize] != 1 || got[skipKty] != 0 {
		t.Fatal("skipped keys report", got)
	}
	// A token naming a skipped key gets exactly the outcome of a token with a kid
	// absent from the snapshot: it is rejected, never verified.
	if _, err := v.VerifyService(context.Background(), sign(t, k.p384, jwt.SigningMethodES384, "p384", claims)); err == nil {
		t.Fatal("token of a skipped key accepted")
	}
	if _, err := v.VerifyService(context.Background(), sign(t, k.p384, jwt.SigningMethodES384, "absent", claims)); err == nil {
		t.Fatal("token of an absent key accepted")
	}
	if got := rejects.take(); len(got) != 2 || got[0] != got[1] || got[0].kind != "service" {
		t.Fatal("skipped kid outcome differs from unknown kid", got)
	}
	// A failed refresh installs nothing and reports nothing.
	fail = true
	now = now.Add(time.Hour)
	_, _ = v.VerifyService(context.Background(), sign(t, k.rsa2048, jwt.SigningMethodRS256, "rsa", claims))
	if got := observer.take(); len(got) != 0 {
		t.Fatal("failed refresh reported", got)
	}
	// A clean snapshot resets every reason to zero.
	fail = false
	body = jwkSet(t, k.ed)
	now = now.Add(time.Minute)
	if err := cache.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := observer.take()
	for reason := range want {
		if c, ok := got[reason]; !ok || c != 0 {
			t.Fatal("reason not reset", reason, got)
		}
	}
	// A plain cache has no observer to call.
	plain, err := NewKeyCache(provider, clock, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
}

type rejectRecord struct{ kind, reason string }

type observerRecorder struct {
	mu      sync.Mutex
	records []rejectRecord
}

func (o *observerRecorder) Reject(kind, reason string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.records = append(o.records, rejectRecord{kind, reason})
}

func (o *observerRecorder) take() []rejectRecord {
	o.mu.Lock()
	defer o.mu.Unlock()
	got := o.records
	o.records = nil
	return got
}

func TestUnitMetricsSkippedKeysBoundedLabels(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, err := NewMetrics(reg)
	if err != nil {
		t.Fatal(err)
	}
	m.SkippedKeys("service", skipCrv, 2)
	m.SkippedKeys("user", skipUse, -1)
	m.SkippedKeys("access", skipCrv, 5)
	m.SkippedKeys("service", "kid-secret", 5)
	got := skippedGauge(t, reg)
	if len(got) != 2 || got["service/crv"] != 2 || got["user/use"] != 0 {
		t.Fatal("unbounded or wrong series", got)
	}
	m.SkippedKeys("service", skipCrv, 0)
	if got := skippedGauge(t, reg); got["service/crv"] != 0 {
		t.Fatal("gauge not reset", got)
	}
	// A conflicting gauge does not leave the counter registered behind.
	conflict := prometheus.NewRegistry()
	if err := conflict.Register(prometheus.NewGauge(prometheus.GaugeOpts{Name: "finassist_identity_jwks_skipped_keys", Help: "x"})); err != nil {
		t.Fatal(err)
	}
	if _, err := NewMetrics(conflict); err == nil {
		t.Fatal("conflicting gauge accepted")
	}
	if _, err := NewMetrics(conflict); err == nil {
		t.Fatal("conflicting gauge accepted on retry")
	}
	families, err := conflict.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == "finassist_identity_rejected_total" {
			t.Fatal("counter left registered")
		}
	}
}

// skippedGauge returns finassist_identity_jwks_skipped_keys values by "kind/reason".
func skippedGauge(t *testing.T, reg prometheus.Gatherer) map[string]float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, f := range families {
		if f.GetName() != "finassist_identity_jwks_skipped_keys" {
			continue
		}
		for _, m := range f.Metric {
			labels := map[string]string{}
			for _, l := range m.Label {
				labels[l.GetName()] = l.GetValue()
			}
			got[labels["kind"]+"/"+labels["reason"]] = m.GetGauge().GetValue()
		}
	}
	return got
}
