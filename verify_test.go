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
	"fmt"
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

func TestUnitUserTokens(t *testing.T) {
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
		{name: "future iat", mutate: func(c *jwt.RegisteredClaims) { c.IssuedAt = jwt.NewNumericDate(now.Add(clockSkew + time.Second)) }},
		{name: "future nbf", mutate: func(c *jwt.RegisteredClaims) { c.NotBefore = jwt.NewNumericDate(now.Add(clockSkew + time.Second)) }},
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

func TestUnitAlgorithms(t *testing.T) {
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
			v, e := newVerifier(opts(&now), []string{tc.name}, func(context.Context, string) (verificationKey, error) { return keys.byKID["k"], nil })
			if e != nil {
				t.Fatal(e)
			}
			if _, _, e := v.parse(context.Background(), sign(t, tc.key, tc.alg, "k", baseClaims(now)), "user"); e != nil {
				t.Fatal(e)
			}
			wrong := keys.byKID["k"]
			wrong.algorithm = "wrong"
			v.key = func(context.Context, string) (verificationKey, error) { return wrong, nil }
			if _, _, e := v.parse(context.Background(), sign(t, tc.key, tc.alg, "k", baseClaims(now)), "user"); e == nil {
				t.Fatal("algorithm mismatch admitted")
			}
		})
	}
}

func TestUnitKeyCacheRotationAndFailure(t *testing.T) {
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

func TestUnitKeyCacheConcurrentAndCancelled(t *testing.T) {
	p, _ := testKey(t)
	now := time.Unix(1700000000, 0)
	var calls atomic.Int32
	c, _ := NewKeyCache(providerFunc(func(context.Context) ([]byte, error) {
		calls.Add(1)
		return jwks(t, map[string]ed25519.PublicKey{"one": p}), nil
	}), func() time.Time { return now }, 2*time.Minute)
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

func TestUnitParseJWKSInvalid(t *testing.T) {
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

func TestUnitKubernetesAndStageBinding(t *testing.T) {
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

func TestUnitConstructors(t *testing.T) {
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

func TestUnitAdditionalKeyValidation(t *testing.T) {
	pub, _ := testKey(t)
	valid := string(jwks(t, map[string]ed25519.PublicKey{"one": pub}))
	if _, e := parseJWKS([]byte(strings.Replace(valid, `"kty":"OKP"`, `"key_ops":["verify"],"use":"sig","kty":"OKP"`, 1))); e != nil {
		t.Fatal(e)
	}
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	for _, key := range []map[string]string{
		{"kid": "k", "kty": "OKP", "crv": "Ed25519", "x": "bad!"},
		{"kid": "k", "kty": "EC", "crv": "P-256", "x": enc(make([]byte, 32)), "y": enc(make([]byte, 32))},
		{"kid": "k", "kty": "RSA", "n": enc(append([]byte{128}, make([]byte, 255)...)), "e": "Ag"},
		{"kid": "k", "kty": "RSA", "n": enc(make([]byte, 256)), "e": "Aw"},
	} {
		data, _ := json.Marshal(map[string]any{"keys": []any{key}})
		if _, e := parseJWKS(data); e == nil {
			t.Fatal("bad JWK accepted")
		}
	}
	now := time.Unix(1, 0)
	cache, _ := NewKeyCache(providerFunc(func(context.Context) ([]byte, error) { return nil, nil }), func() time.Time { return now }, 2*time.Minute)
	if _, e := NewUserVerifier(cache, VerifyOptions{}); e == nil {
		t.Fatal("user invalid options")
	}
	if _, e := NewKubernetesVerifier(cache, VerifyOptions{Audience: "finassist-internal"}, "finassist"); e == nil {
		t.Fatal("service invalid options")
	}
	_, private := testKey(t)
	o := VerifyOptions{Issuer: "stage", Audience: "finassist-internal", Clock: func() time.Time { return now }}
	v, e := NewStageVerifier("stage", o, map[string]ed25519.PublicKey{"bank-bff": pub})
	if e != nil {
		t.Fatal(e)
	}
	c := baseClaims(now)
	c.Issuer = "stage"
	c.Audience = jwt.ClaimStrings{"finassist-internal"}
	c.Subject = "assistant"
	if _, e = v.VerifyService(context.Background(), sign(t, private, jwt.SigningMethodEdDSA, "assistant", c)); e == nil {
		t.Fatal("unknown stage key")
	}
}

// arrivalContext reports when a request reaches the refresh select. This lets the
// test hold the provider until every concurrent request has actually arrived,
// without timing sleeps or relying on goroutine scheduling.
type arrivalContext struct {
	context.Context
	arrived chan<- struct{}
	once    sync.Once
}

func (c *arrivalContext) Done() <-chan struct{} {
	c.once.Do(func() { c.arrived <- struct{}{} })
	return c.Context.Done()
}

func TestUnitUnknownKeyConcurrentFailedRefresh(t *testing.T) {
	now := time.Unix(1700000000, 0)
	var calls atomic.Int32
	held := make(chan struct{})
	entered := make(chan struct{})
	arrived := make(chan struct{}, 24)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cache, e := NewKeyCache(providerFunc(func(ctx context.Context) ([]byte, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-held:
			return nil, errors.New("upstream secret")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}), func() time.Time { return now }, 10*time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 24 {
		wg.Go(func() {
			<-start
			requestCtx := &arrivalContext{Context: ctx, arrived: arrived}
			if _, e := cache.key(requestCtx, "unknown"); e == nil {
				t.Error("unknown key admitted after failed refresh")
			}
		})
	}
	close(start)
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("provider did not start")
	}
	for range 24 {
		select {
		case <-arrived:
		case <-ctx.Done():
			t.Fatal("requests did not reach held refresh")
		}
	}
	if calls.Load() != 1 {
		t.Errorf("parallel provider calls: %d", calls.Load())
	}
	close(held)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("waiters did not finish")
	}
	for range 24 {
		if _, e := cache.key(ctx, "another-unknown"); e == nil {
			t.Fatal("unknown key admitted")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("failed refresh retried before limit: %d", calls.Load())
	}
	now = now.Add(time.Minute)
	if _, e := cache.key(ctx, "unknown"); e == nil {
		t.Fatal("failed refresh admitted")
	}
	if calls.Load() != 2 {
		t.Fatal("refresh did not retry after limit")
	}
}

func TestUnitRefreshSurvivesRequestCancellation(t *testing.T) {
	for _, during := range []bool{false, true} {
		t.Run(fmt.Sprint("during_fetch=", during), func(t *testing.T) {
			now := time.Unix(1700000000, 0)
			pub, _ := testKey(t)
			data := jwks(t, map[string]ed25519.PublicKey{"one": pub})
			var calls atomic.Int32
			entered := make(chan struct{})
			release := make(chan struct{})
			cache, _ := NewKeyCache(providerFunc(func(ctx context.Context) ([]byte, error) {
				if calls.Add(1) == 2 && during {
					close(entered)
					select {
					case <-release:
						if err := ctx.Err(); err != nil {
							return nil, err
						}
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				return data, nil
			}), func() time.Time { return now }, 2*time.Minute)
			if _, e := cache.key(context.Background(), "one"); e != nil {
				t.Fatal(e)
			}
			now = now.Add(2 * time.Minute)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if during {
				done := make(chan error, 1)
				go func() { _, e := cache.key(ctx, "one"); done <- e }()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("fetch not started")
				}
				cancel()
				close(release)
				select {
				case e := <-done:
					if !errors.Is(e, context.Canceled) {
						t.Fatal("cancelled request received identity", e)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("fetch stuck")
				}
			} else {
				cancel()
				if _, e := cache.key(ctx, "one"); !errors.Is(e, context.Canceled) {
					t.Fatal(e)
				}
				if calls.Load() != 1 {
					t.Fatal("cancelled request spent refresh slot")
				}
			}
			if _, e := cache.key(context.Background(), "one"); e != nil {
				t.Fatal("live request failed after cancellation", e)
			}
			if calls.Load() != 2 {
				t.Fatalf("refresh count=%d", calls.Load())
			}
		})
	}
}

func TestUnitClockSkewDoesNotExtendExpiration(t *testing.T) {
	now := time.Unix(1700000000, 0)
	pub, key := testKey(t)
	v := userVerifier(t, pub, &now)
	for _, offset := range []time.Duration{time.Second, clockSkew, clockSkew + time.Second} {
		c := baseClaims(now)
		c.IssuedAt = jwt.NewNumericDate(now.Add(offset))
		c.NotBefore = jwt.NewNumericDate(now.Add(offset))
		_, e := v.VerifyUser(context.Background(), sign(t, key, jwt.SigningMethodEdDSA, "one", c))
		if (e == nil) != (offset <= clockSkew) {
			t.Fatalf("offset=%v error=%v", offset, e)
		}
	}
	for _, expiration := range []time.Time{now, now.Add(-time.Second)} {
		c := baseClaims(now)
		c.ExpiresAt = jwt.NewNumericDate(expiration)
		if _, e := v.VerifyUser(context.Background(), sign(t, key, jwt.SigningMethodEdDSA, "one", c)); e == nil {
			t.Fatal("skew extended exp")
		}
	}
}

func TestUnitRefreshWaiterCancellation(t *testing.T) {
	now := time.Unix(1, 0)
	cache, _ := NewKeyCache(providerFunc(func(context.Context) ([]byte, error) { t.Fatal("waiter started another fetch"); return nil, nil }), func() time.Time { return now }, 2*time.Minute)
	cache.gate <- struct{}{}
	defer func() { <-cache.gate }()
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	arrived := make(chan struct{}, 1)
	ctx := &arrivalContext{Context: parent, arrived: arrived}
	done := make(chan error, 1)
	go func() { done <- cache.refresh(ctx) }()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("waiter did not enter gate")
	}
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter ignored cancellation")
	}
	if cache.hasAttempt {
		t.Fatal("cancelled waiter consumed refresh slot")
	}
}

func TestUnitProactiveRefreshRetriesWithinSnapshotLifetime(t *testing.T) {
	now := time.Unix(1700000000, 0)
	pub, _ := testKey(t)
	data := jwks(t, map[string]ed25519.PublicKey{"one": pub})
	calls := 0
	fail := false
	cache, _ := NewKeyCache(providerFunc(func(context.Context) ([]byte, error) {
		calls++
		if fail {
			return nil, errors.New("rolling deployment")
		}
		return data, nil
	}), func() time.Time { return now }, 10*time.Minute)
	cache.refreshIfDue(context.Background())
	if calls != 1 {
		t.Fatal("missing initial refresh")
	}
	now = now.Add(5*time.Minute - time.Nanosecond)
	cache.refreshIfDue(context.Background())
	if calls != 1 {
		t.Fatal("refreshed before proactive boundary")
	}
	now = now.Add(time.Nanosecond)
	fail = true
	cache.refreshIfDue(context.Background())
	if calls != 2 {
		t.Fatal("did not proactively refresh at half age")
	}
	if _, e := cache.key(context.Background(), "one"); e != nil {
		t.Fatal("one proactive failure rejected known key", e)
	}
	now = now.Add(time.Minute)
	fail = false
	cache.refreshIfDue(context.Background())
	if calls != 3 {
		t.Fatal("did not retry next minute")
	}
	now = now.Add(5*time.Minute - time.Nanosecond)
	cache.refreshIfDue(context.Background())
	if calls != 3 {
		t.Fatal("successful refresh did not reset schedule")
	}
	if _, e := cache.key(context.Background(), "one"); e != nil {
		t.Fatal("replacement snapshot unavailable", e)
	}
}

func TestUnitKeyCacheRunControlledTicks(t *testing.T) {
	var instant atomic.Int64
	instant.Store(time.Unix(1700000000, 0).UnixNano())
	clock := func() time.Time { return time.Unix(0, instant.Load()) }
	pub, _ := testKey(t)
	data := jwks(t, map[string]ed25519.PublicKey{"one": pub})
	fetched := make(chan struct{}, 2)
	cache, _ := NewKeyCache(providerFunc(func(context.Context) ([]byte, error) { fetched <- struct{}{}; return data, nil }), clock, 10*time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ticks := make(chan time.Time)
	done := make(chan error, 1)
	go func() { done <- cache.run(ctx, ticks) }()
	select {
	case <-fetched:
	case <-ctx.Done():
		t.Fatal("initial job load absent")
	}
	// Wait for publication of the first fetch before moving the injected clock.
	select {
	case cache.gate <- struct{}{}:
		<-cache.gate
	case <-ctx.Done():
		t.Fatal("initial publication stuck")
	}
	instant.Add(int64(5 * time.Minute))
	select {
	case ticks <- clock():
	case <-ctx.Done():
		t.Fatal("job not listening for ticks")
	}
	select {
	case <-fetched:
	case <-ctx.Done():
		t.Fatal("tick did not refresh")
	}
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("job did not stop")
	}
}

func TestUnitKeyCacheMinimumAgeAllowsProactiveRefresh(t *testing.T) {
	provider := providerFunc(func(context.Context) ([]byte, error) { return nil, nil })
	if _, e := NewKeyCache(provider, time.Now, time.Minute); e == nil {
		t.Fatal("snapshot age leaves no room before refresh limit")
	}
	if _, e := NewKeyCache(provider, time.Now, 2*time.Minute); e != nil {
		t.Fatal(e)
	}
}

func TestUnitRefreshTickJitterRetriesWithinNinetySeconds(t *testing.T) {
	origin := time.Unix(1700000000, 0)
	now := origin
	pub, _ := testKey(t)
	data := jwks(t, map[string]ed25519.PublicKey{"one": pub})
	calls := 0
	fail := false
	cache, _ := NewKeyCache(providerFunc(func(context.Context) ([]byte, error) {
		calls++
		if fail {
			return nil, errors.New("upstream temporarily down")
		}
		return data, nil
	}), func() time.Time { return now }, 10*time.Minute)
	cache.refreshIfDue(context.Background())
	fail = true
	// This tick was handled 1 ms late. The next nominal minute is still inside
	// the limiter window; the intermediate poll must recover by 90 seconds.
	now = origin.Add(5*time.Minute + time.Millisecond)
	cache.refreshIfDue(context.Background())
	if calls != 2 {
		t.Fatal("failed attempt missing")
	}
	fail = false
	for offset := refreshCheckPeriod; offset <= 90*time.Second; offset += refreshCheckPeriod {
		now = origin.Add(5*time.Minute + offset)
		cache.refreshIfDue(context.Background())
		if offset <= time.Minute && calls != 2 {
			t.Fatal("minute limit bypassed")
		}
	}
	if calls != 3 {
		t.Fatalf("retry missed 90-second bound: %d fetches", calls)
	}
	if _, e := cache.key(context.Background(), "one"); e != nil {
		t.Fatal("recovered snapshot unavailable", e)
	}
}
