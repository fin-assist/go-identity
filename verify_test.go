package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fin-assist/contracts/gen/go/finerr"
	"github.com/golang-jwt/jwt/v5"
)

type providerFunc func(context.Context) ([]byte, error)

func (f providerFunc) JWKS(ctx context.Context) ([]byte, error) { return f(ctx) }
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
func opts(now *time.Time) VerifyOptions {
	return VerifyOptions{Issuer: "user", Audience: "finassist", Clock: func() time.Time { return *now }}
}
func baseClaims(now time.Time) jwt.RegisteredClaims {
	return jwt.RegisteredClaims{Issuer: "user", Subject: "user-1", Audience: jwt.ClaimStrings{"finassist"}, ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)), IssuedAt: jwt.NewNumericDate(now)}
}
func userVerifier(t *testing.T, pub ed25519.PublicKey, now *time.Time) *UserVerifier {
	t.Helper()
	c, e := NewKeyCache(providerFunc(func(context.Context) ([]byte, error) { return jwks(t, map[string]ed25519.PublicKey{"one": pub}), nil }), func() time.Time { return *now }, 10*time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	v, e := NewUserVerifier(c, opts(now))
	if e != nil {
		t.Fatal(e)
	}
	return v
}

type observer struct {
	mu      sync.Mutex
	reasons []string
}

func (o *observer) Reject(kind, reason string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.reasons = append(o.reasons, kind+":"+reason)
}

func TestUserTokens(t *testing.T) {
	now := time.Unix(1700000000, 0)
	pub, key := testKey(t)
	_, foreign := testKey(t)
	v := userVerifier(t, pub, &now)
	cases := []struct {
		name   string
		mutate func(*jwt.RegisteredClaims)
		key    any
		method jwt.SigningMethod
		kid    string
		good   bool
	}{
		{name: "valid", good: true}, {name: "expired", mutate: func(c *jwt.RegisteredClaims) { c.ExpiresAt = jwt.NewNumericDate(now) }},
		{name: "no expiry", mutate: func(c *jwt.RegisteredClaims) { c.ExpiresAt = nil }},
		{name: "wrong audience", mutate: func(c *jwt.RegisteredClaims) { c.Audience = jwt.ClaimStrings{"other"} }},
		{name: "wrong issuer", mutate: func(c *jwt.RegisteredClaims) { c.Issuer = "other" }},
		{name: "empty subject", mutate: func(c *jwt.RegisteredClaims) { c.Subject = " " }},
		{name: "long subject", mutate: func(c *jwt.RegisteredClaims) { c.Subject = strings.Repeat("s", 257) }},
		{name: "future iat", mutate: func(c *jwt.RegisteredClaims) { c.IssuedAt = jwt.NewNumericDate(now.Add(time.Second)) }},
		{name: "future nbf", mutate: func(c *jwt.RegisteredClaims) { c.NotBefore = jwt.NewNumericDate(now.Add(time.Second)) }},
		{name: "bad signature", key: foreign}, {name: "unknown kid", kid: "unknown"},
		{name: "symmetric confusion", key: []byte(pub), method: jwt.SigningMethodHS256},
		{name: "none", key: jwt.UnsafeAllowNoneSignatureType, method: jwt.SigningMethodNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := baseClaims(now)
			if tc.mutate != nil {
				tc.mutate(&c)
			}
			k := tc.key
			if k == nil {
				k = key
			}
			m := tc.method
			if m == nil {
				m = jwt.SigningMethodEdDSA
			}
			kid := tc.kid
			if kid == "" {
				kid = "one"
			}
			raw := sign(t, k, m, kid, c)
			id, e := v.VerifyUser(context.Background(), raw)
			if tc.good {
				if e != nil || id != "user-1" {
					t.Fatalf("id=%q err=%v", id, e)
				}
			} else {
				rest, ok := finerr.ToREST(e)
				if !ok || rest.Code != "INVALID_TOKEN" || id != "" {
					t.Fatalf("not INVALID_TOKEN: %v", e)
				}
				if strings.Contains(e.Error(), raw) {
					t.Fatal("token leaked")
				}
			}
		})
	}
	for _, raw := range []string{"", strings.Repeat("x", maxToken+1), "bad", sign(t, key, jwt.SigningMethodEdDSA, "", baseClaims(now))} {
		if _, e := v.VerifyUser(context.Background(), raw); e == nil {
			t.Fatal("invalid input admitted")
		}
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, baseClaims(now))
	token.Header["kid"] = "one"
	token.Header["crit"] = []string{"custom"}
	raw, _ := token.SignedString(key)
	if _, e := v.VerifyUser(context.Background(), raw); e == nil {
		t.Fatal("critical extension admitted")
	}
}

func TestAlgorithms(t *testing.T) {
	now := time.Unix(1700000000, 0)
	ec, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	rsaKey, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	cases := []struct {
		name string
		jwk  map[string]string
		key  any
		alg  jwt.SigningMethod
	}{
		{"ES256", map[string]string{"kid": "k", "kty": "EC", "crv": "P-256", "x": enc(ec.X.FillBytes(make([]byte, 32))), "y": enc(ec.Y.FillBytes(make([]byte, 32)))}, ec, jwt.SigningMethodES256},
		{"RS256", map[string]string{"kid": "k", "kty": "RSA", "n": enc(rsaKey.N.Bytes()), "e": enc(big.NewInt(int64(rsaKey.E)).Bytes())}, rsaKey, jwt.SigningMethodRS256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := json.Marshal(map[string]any{"keys": []any{tc.jwk}})
			keys, e := parseJWKS(b)
			if e != nil {
				t.Fatal(e)
			}
			v, e := newVerifier(opts(&now), []string{tc.name}, func(context.Context, string) (verificationKey, error) { return keys["k"], nil })
			if e != nil {
				t.Fatal(e)
			}
			if _, _, e := v.parse(context.Background(), sign(t, tc.key, tc.alg, "k", baseClaims(now)), "user"); e != nil {
				t.Fatal(e)
			}
			wrong := keys["k"]
			wrong.algorithm = "wrong"
			v.key = func(context.Context, string) (verificationKey, error) { return wrong, nil }
			if _, _, e := v.parse(context.Background(), sign(t, tc.key, tc.alg, "k", baseClaims(now)), "user"); e == nil {
				t.Fatal("algorithm mismatch admitted")
			}
		})
	}
}

func TestKeyCacheRotationAndFailure(t *testing.T) {
	now := time.Unix(1700000000, 0)
	p, _ := testKey(t)
	p2, _ := testKey(t)
	data := jwks(t, map[string]ed25519.PublicKey{"one": p})
	calls := 0
	fail := false
	cache, e := NewKeyCache(providerFunc(func(context.Context) ([]byte, error) {
		calls++
		if fail {
			return nil, errors.New("secret transport detail")
		}
		return data, nil
	}), func() time.Time { return now }, 10*time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = cache.key(context.Background(), "one"); e != nil {
		t.Fatal(e)
	}
	data = jwks(t, map[string]ed25519.PublicKey{"one": p, "two": p2})
	for range 10 {
		if _, e = cache.key(context.Background(), "two"); e == nil {
			t.Fatal("unexpected refresh")
		}
	}
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
	now = now.Add(time.Minute)
	if _, e = cache.key(context.Background(), "two"); e != nil {
		t.Fatal(e)
	}
	// Publishing overlapping sets permits both old and new tokens.
	if _, e = cache.key(context.Background(), "one"); e != nil {
		t.Fatal(e)
	}
	now = now.Add(time.Minute)
	data = jwks(t, map[string]ed25519.PublicKey{"two": p2})
	if e = cache.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	if _, e = cache.key(context.Background(), "one"); e == nil {
		t.Fatal("removed key accepted")
	}
	now = now.Add(10 * time.Minute)
	fail = true
	if _, e = cache.key(context.Background(), "two"); e == nil {
		t.Fatal("stale snapshot accepted")
	}
	for range 10 {
		_, _ = cache.key(context.Background(), "two")
	}
	if calls != 4 {
		t.Fatalf("failed refresh storm: %d", calls)
	}
	now = now.Add(time.Minute)
	fail = false
	data = []byte("bad")
	if e = cache.refresh(context.Background()); e == nil {
		t.Fatal("bad snapshot")
	}
}

func TestKeyCacheConcurrentAndCancelled(t *testing.T) {
	p, _ := testKey(t)
	now := time.Unix(1700000000, 0)
	var calls atomic.Int32
	c, _ := NewKeyCache(providerFunc(func(context.Context) ([]byte, error) {
		calls.Add(1)
		return jwks(t, map[string]ed25519.PublicKey{"one": p}), nil
	}), func() time.Time { return now }, time.Minute)
	var wg sync.WaitGroup
	for range 30 {
		wg.Go(func() {
			if _, e := c.key(context.Background(), "one"); e != nil {
				t.Error(e)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("concurrent fetches")
	}
	c.gate <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := c.refresh(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	<-c.gate
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if e := c.Run(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func TestParseJWKSInvalid(t *testing.T) {
	pub, _ := testKey(t)
	good := string(jwks(t, map[string]ed25519.PublicKey{"k": pub}))
	for _, s := range []string{"", `{}`, `{"keys":[]}`, strings.Repeat("x", maxJWKS+1), strings.Replace(good, `"Ed25519"`, `"other"`, 1), strings.Replace(good, `"EdDSA"`, `"HS256"`, 1), strings.Replace(good, `"kid":"k"`, `"kid":""`, 1), strings.Replace(good, `"kty":"OKP"`, `"use":"enc","kty":"OKP"`, 1), strings.Replace(good, `"kty":"OKP"`, `"key_ops":["sign"],"kty":"OKP"`, 1), `{"keys":[{"kid":"k","kty":"EC","crv":"P-256","x":"AA","y":"AA"}]}`, `{"keys":[{"kid":"k","kty":"RSA","n":"AA","e":"Aw"}]}`} {
		if _, e := parseJWKS([]byte(s)); e == nil {
			t.Fatalf("accepted %s", s)
		}
	}
	var set struct{ Keys []map[string]any }
	_ = json.Unmarshal([]byte(good), &set)
	set.Keys = append(set.Keys, set.Keys[0])
	b, _ := json.Marshal(set)
	if _, e := parseJWKS(b); e == nil {
		t.Fatal("duplicate kid")
	}
}

func TestKubernetesAndStageBinding(t *testing.T) {
	now := time.Unix(1700000000, 0)
	pub, key := testKey(t)
	cache, _ := NewKeyCache(providerFunc(func(context.Context) ([]byte, error) { return jwks(t, map[string]ed25519.PublicKey{"k": pub}), nil }), func() time.Time { return now }, time.Hour)
	o := opts(&now)
	o.Issuer = "https://kubernetes.default.svc.cluster.local"
	o.Audience = "finassist-internal"
	o.Observer = &observer{}
	v, e := NewKubernetesVerifier(cache, o, "finassist")
	if e != nil {
		t.Fatal(e)
	}
	c := claims{RegisteredClaims: baseClaims(now)}
	c.Issuer = o.Issuer
	c.Audience = jwt.ClaimStrings{o.Audience}
	c.Subject = "system:serviceaccount:finassist:bank-bff"
	c.Kubernetes.Namespace = "finassist"
	c.Kubernetes.ServiceAccount.Name = "bank-bff"
	for index, mutate := range []func(*claims){func(*claims) {}, func(c *claims) { c.Kubernetes.Namespace = "other" }, func(c *claims) { c.Kubernetes.ServiceAccount.Name = "user" }, func(c *claims) { c.Subject = "bank-bff" }} {
		x := c
		mutate(&x)
		id, e := v.VerifyService(context.Background(), sign(t, key, jwt.SigningMethodEdDSA, "k", x))
		if index == 0 {
			if e != nil || id != "bank-bff" {
				t.Fatal(id, e)
			}
		} else if e == nil {
			t.Fatal("mismatch accepted")
		}
	}
	if _, e = v.VerifyService(context.Background(), "bad"); e == nil {
		t.Fatal("malformed accepted")
	}
	o.Issuer = "stage"
	sv, e := NewStageVerifier("stage", o, map[string]ed25519.PublicKey{"bank-bff": pub})
	if e != nil {
		t.Fatal(e)
	}
	sc := baseClaims(now)
	sc.Issuer = o.Issuer
	sc.Audience = jwt.ClaimStrings{o.Audience}
	sc.Subject = "bank-bff"
	if id, e := sv.VerifyService(context.Background(), sign(t, key, jwt.SigningMethodEdDSA, "bank-bff", sc)); e != nil || id != "bank-bff" {
		t.Fatal(id, e)
	}
	for _, mutate := range []func(*jwt.RegisteredClaims){func(c *jwt.RegisteredClaims) { c.Subject = "user" }, func(c *jwt.RegisteredClaims) { c.IssuedAt = nil }, func(c *jwt.RegisteredClaims) { c.ExpiresAt = jwt.NewNumericDate(now.Add(6 * time.Minute)) }} {
		c := sc
		mutate(&c)
		if _, e := sv.VerifyService(context.Background(), sign(t, key, jwt.SigningMethodEdDSA, "bank-bff", c)); e == nil {
			t.Fatal("stage impersonation/lifetime accepted")
		}
	}
	if _, e := sv.VerifyService(context.Background(), "bad"); e == nil {
		t.Fatal("bad stage token")
	}
	for _, env := range []string{"prod", "", "production"} {
		if _, e := NewStageVerifier(env, o, map[string]ed25519.PublicKey{"bank-bff": pub}); e == nil {
			t.Fatal("unsafe environment")
		}
	}
}

func TestConstructors(t *testing.T) {
	now := time.Unix(1, 0)
	pub, _ := testKey(t)
	o := opts(&now)
	if _, e := NewKeyCache(nil, o.Clock, time.Minute); e == nil {
		t.Fatal("nil provider")
	}
	if _, e := NewKeyCache(providerFunc(nil), nil, time.Second); e == nil {
		t.Fatal("nil clock")
	}
	if _, e := NewUserVerifier(nil, o); e == nil {
		t.Fatal("nil cache")
	}
	if _, e := newVerifier(VerifyOptions{}, nil, nil); e == nil {
		t.Fatal("missing issuer")
	}
	if _, e := NewKubernetesVerifier(nil, o, "bad:name"); e == nil {
		t.Fatal("bad Kubernetes config")
	}
	if _, e := NewStageVerifier("stage", o, map[string]ed25519.PublicKey{"x": pub}); e == nil {
		t.Fatal("bad audience")
	}
	o.Audience = "finassist-internal"
	if _, e := NewStageVerifier("stage", o, map[string]ed25519.PublicKey{"BAD": pub}); e == nil {
		t.Fatal("bad caller")
	}
	o.Clock = nil
	if _, e := NewStageVerifier("stage", o, map[string]ed25519.PublicKey{"x": pub}); e == nil {
		t.Fatal("bad stage options")
	}
	for _, n := range []string{"", "-a", "a-", "UPPER", "a:b", strings.Repeat("a", 64)} {
		if serviceName(n) {
			t.Fatal(n)
		}
	}
}
