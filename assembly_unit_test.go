package identity

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
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

// stageJWKS encodes Ed25519 public keys of stage services by name.
func stageJWKS(t *testing.T, keys map[string]ed25519.PublicKey) []byte {
	t.Helper()
	all := []map[string]string{}
	for kid, key := range keys {
		all = append(all, map[string]string{"kid": kid, "kty": "OKP", "crv": "Ed25519", "use": "sig", "x": base64.RawURLEncoding.EncodeToString(key)})
	}
	b, err := json.Marshal(map[string]any{"keys": all})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// caPEM is a self-signed CA certificate; NewAssembly only parses it.
func caPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cluster CA"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<32, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// metricsFree reports whether the identity metrics can still be registered,
// that is whether a refused assembly left nothing in the registry.
func metricsFree(reg prometheus.Registerer) bool {
	_, err := NewMetrics(reg)
	return err == nil
}

func prodOptions(t *testing.T, reg prometheus.Registerer) AssemblyOptions {
	t.Helper()
	pub, _ := testKey(t)
	return AssemblyOptions{
		Env: "prod", Service: "analytics", UserIssuer: "user", UserAudience: "finassist",
		UserKeys:   providerFunc(func(context.Context) ([]byte, error) { return jwks(t, map[string]ed25519.PublicKey{"one": pub}), nil }),
		Kubernetes: KubernetesOptions{TokenFile: "/var/run/secrets/finassist/token", CAFile: writeFile(t, "ca.crt", caPEM(t))},
		Clock:      time.Now, Registerer: reg,
	}
}

func TestUnitAssemblyRejectsInvalidOptions(t *testing.T) {
	dial := func(TokenSource) (*grpc.ClientConn, error) { return nil, errors.New("not dialed") }
	cases := map[string]func(*AssemblyOptions){
		"empty env":           func(o *AssemblyOptions) { o.Env = "" },
		"dev env":             func(o *AssemblyOptions) { o.Env = "dev" },
		"unknown env":         func(o *AssemblyOptions) { o.Env = "production" },
		"case-changed env":    func(o *AssemblyOptions) { o.Env = "Prod" },
		"no service":          func(o *AssemblyOptions) { o.Service = "" },
		"bad service":         func(o *AssemblyOptions) { o.Service = "Analytics" },
		"no clock":            func(o *AssemblyOptions) { o.Clock = nil },
		"no registry":         func(o *AssemblyOptions) { o.Registerer = nil },
		"no user issuer":      func(o *AssemblyOptions) { o.UserIssuer = " " },
		"no user audience":    func(o *AssemblyOptions) { o.UserAudience = "" },
		"no user keys":        func(o *AssemblyOptions) { o.UserKeys = nil },
		"two user key paths":  func(o *AssemblyOptions) { o.DialUser = dial },
		"no service token":    func(o *AssemblyOptions) { o.Kubernetes.TokenFile = "" },
		"shared token file":   func(o *AssemblyOptions) { o.Kubernetes.TokenFile = defaultKubernetesAPITokenFile },
		"shared custom token": func(o *AssemblyOptions) { o.Kubernetes.APITokenFile = o.Kubernetes.TokenFile },
		"shared token via dot": func(o *AssemblyOptions) {
			o.Kubernetes.TokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/./token"
		},
		"shared token via double slash": func(o *AssemblyOptions) {
			o.Kubernetes.TokenFile = "/var/run/secrets/kubernetes.io/serviceaccount//token"
		},
		"bad namespace": func(o *AssemblyOptions) { o.Kubernetes.Namespace = "Finassist" },
		"blank issuer":  func(o *AssemblyOptions) { o.Kubernetes.Issuer = " " },
		"stage issuer in prod": func(o *AssemblyOptions) {
			o.Stage.Issuer = "stage"
		},
		"stage key in prod":    func(o *AssemblyOptions) { o.Stage.SigningKeyFile = "/keys/assistant.pem" },
		"stage public in prod": func(o *AssemblyOptions) { o.Stage.PublicKeysFile = "/keys/services.json" },
		"stage without issuer": func(o *AssemblyOptions) {
			o.Env, o.Stage = "stage", StageKeyFiles{SigningKeyFile: "k", PublicKeysFile: "p"}
		},
		"stage without key": func(o *AssemblyOptions) {
			o.Env, o.Stage = "stage", StageKeyFiles{Issuer: "stage", PublicKeysFile: "p"}
		},
		"stage without public": func(o *AssemblyOptions) {
			o.Env, o.Stage = "stage", StageKeyFiles{Issuer: "stage", SigningKeyFile: "k"}
		},
		"missing CA file":        func(o *AssemblyOptions) { o.Kubernetes.CAFile = filepath.Join(t.TempDir(), "absent.crt") },
		"CA directory":           func(o *AssemblyOptions) { o.Kubernetes.CAFile = t.TempDir() },
		"CA without certificate": func(o *AssemblyOptions) { o.Kubernetes.CAFile = writeFile(t, "ca.crt", []byte("secret-not-a-cert")) },
		"oversized CA":           func(o *AssemblyOptions) { o.Kubernetes.CAFile = writeFile(t, "ca.crt", make([]byte, maxCAFile+1)) },
		"plain HTTP JWKS":        func(o *AssemblyOptions) { o.Kubernetes.JWKSURL = "http://kubernetes.default.svc/openid/v1/jwks" },
		"JWKS with query":        func(o *AssemblyOptions) { o.Kubernetes.JWKSURL = "https://kubernetes.default.svc/jwks?secret=x" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			o := prodOptions(t, reg)
			mutate(&o)
			a, err := NewAssembly(o)
			if err == nil || a != nil {
				t.Fatal("invalid options accepted")
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "/") {
				t.Fatal("error leaks configuration", err)
			}
			if !metricsFree(reg) {
				t.Fatal("refused assembly left metrics registered")
			}
		})
	}
}

func TestUnitKubernetesDefaults(t *testing.T) {
	got := KubernetesOptions{TokenFile: "/t"}.withDefaults()
	want := KubernetesOptions{TokenFile: "/t", Issuer: defaultKubernetesIssuer, JWKSURL: defaultKubernetesJWKSURL, CAFile: defaultKubernetesCAFile, APITokenFile: defaultKubernetesAPITokenFile, Namespace: "finassist"}
	if got != want {
		t.Fatal(got)
	}
	custom := KubernetesOptions{TokenFile: "/t", Issuer: "i", JWKSURL: "u", CAFile: "c", APITokenFile: "a", Namespace: "n"}
	if custom.withDefaults() != custom {
		t.Fatal("explicit values replaced")
	}
}

func TestUnitAssemblyProdBuildsWithoutNetwork(t *testing.T) {
	reg := prometheus.NewRegistry()
	o := prodOptions(t, reg)
	a, err := NewAssembly(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.caches) != 2 || a.transport == nil || a.conn != nil {
		t.Fatal("prod assembly must own user and Kubernetes caches and the JWKS transport")
	}
	if _, ok := a.services.(*KubernetesVerifier); !ok {
		t.Fatal("prod must verify Kubernetes ServiceAccount tokens")
	}
	// Only CAFile is trusted and no proxy from the environment sees the API token.
	if a.transport.Proxy != nil || a.transport.TLSClientConfig.InsecureSkipVerify || a.transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("JWKS transport must trust only the configured CA, without a proxy")
	}
	if _, ok := a.tokens.(*ProjectedSource); !ok {
		t.Fatal("prod must send the projected token")
	}
	if metricsFree(reg) {
		t.Fatal("assembly metrics not registered")
	}
	// A second assembly in the same registry is a configuration error, not a shared state.
	if _, err := NewAssembly(o); err == nil {
		t.Fatal("duplicate registration accepted")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal("repeated close", err)
	}
}

func TestUnitAssemblyDialUser(t *testing.T) {
	var gotTokens TokenSource
	o := prodOptions(t, prometheus.NewRegistry())
	o.UserKeys = nil
	o.DialUser = func(source TokenSource) (*grpc.ClientConn, error) {
		gotTokens = source
		return grpc.NewClient("passthrough:///user", grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	a, err := NewAssembly(o)
	if err != nil {
		t.Fatal(err)
	}
	if gotTokens != a.tokens || a.conn == nil {
		t.Fatal("user connection must use the assembly's outgoing token source")
	}
	if a.Close() != nil {
		t.Fatal("close failed")
	}
	newConn := func(t *testing.T) *grpc.ClientConn {
		c, err := grpc.NewClient("passthrough:///user", grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	cases := map[string]struct {
		dial     func(*testing.T, **grpc.ClientConn) func(TokenSource) (*grpc.ClientConn, error)
		occupied bool // metrics already registered: the failure comes after a successful dial
	}{
		"error": {dial: func(*testing.T, **grpc.ClientConn) func(TokenSource) (*grpc.ClientConn, error) {
			return func(TokenSource) (*grpc.ClientConn, error) { return nil, errors.New("dial secret-target") }
		}},
		"nil conn": {dial: func(*testing.T, **grpc.ClientConn) func(TokenSource) (*grpc.ClientConn, error) {
			return func(TokenSource) (*grpc.ClientConn, error) { return nil, nil }
		}},
		"conn and error": {dial: func(t *testing.T, got **grpc.ClientConn) func(TokenSource) (*grpc.ClientConn, error) {
			return func(TokenSource) (*grpc.ClientConn, error) { *got = newConn(t); return *got, errors.New("partial") }
		}},
		"metrics conflict after dial": {occupied: true, dial: func(t *testing.T, got **grpc.ClientConn) func(TokenSource) (*grpc.ClientConn, error) {
			return func(TokenSource) (*grpc.ClientConn, error) { *got = newConn(t); return *got, nil }
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			if tc.occupied && !metricsFree(reg) {
				t.Fatal("registry not prepared")
			}
			var conn *grpc.ClientConn
			o := prodOptions(t, reg)
			o.UserKeys, o.DialUser = nil, tc.dial(t, &conn)
			if _, err := NewAssembly(o); err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatal("dial failure accepted or leaked", err)
			}
			if !tc.occupied && !metricsFree(reg) {
				t.Fatal("refused assembly left metrics registered")
			}
			if conn != nil && conn.GetState() != connectivity.Shutdown {
				t.Fatal("refused assembly left the user connection open", conn.GetState())
			}
		})
	}
}

func TestUnitParseStagePublicKeys(t *testing.T) {
	pub, _ := testKey(t)
	keys, err := parseStagePublicKeys(stageJWKS(t, map[string]ed25519.PublicKey{"assistant": pub, "bank-bff": pub}))
	if err != nil || len(keys) != 2 || !keys["assistant"].Equal(pub) {
		t.Fatal(keys, err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	okp := map[string]any{"kid": "assistant", "kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}
	for name, set := range map[string]any{
		"EC key":          []any{okp, ecJWK("bank-bff", ec, "P-256", "ES256")},
		"unsupported kty": []any{okp, map[string]any{"kid": "user", "kty": "oct", "k": "AA"}},
		"encryption key":  []any{okp, map[string]any{"kid": "user", "kty": "OKP", "crv": "Ed25519", "use": "enc", "x": base64.RawURLEncoding.EncodeToString(pub)}},
		"non-service kid": []any{map[string]any{"kid": "Assistant", "kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}},
		"duplicate kid":   []any{okp, okp},
		"empty set":       []any{},
		"broken material": []any{map[string]any{"kid": "assistant", "kty": "OKP", "crv": "Ed25519", "x": "short"}},
	} {
		b, _ := json.Marshal(map[string]any{"keys": set})
		if _, err := parseStagePublicKeys(b); err == nil {
			t.Fatal(name, "accepted")
		}
	}
	if _, err := parseStagePublicKeys([]byte("{")); err == nil {
		t.Fatal("broken JSON accepted")
	}
}

type stageFixture struct {
	options     AssemblyOptions
	servicePriv map[string]ed25519.PrivateKey
	userPriv    ed25519.PrivateKey
	now         *time.Time
}

// newStageFixture writes the files of one stage service named service, trusting
// assistant, bank-bff and itself.
func newStageFixture(t *testing.T, service string) stageFixture {
	t.Helper()
	now := time.Unix(1700000000, 0)
	f := stageFixture{servicePriv: map[string]ed25519.PrivateKey{}, now: &now}
	public := map[string]ed25519.PublicKey{}
	for _, name := range []string{"assistant", "bank-bff", service} {
		pub, priv := testKey(t)
		public[name], f.servicePriv[name] = pub, priv
	}
	userPub, userPriv := testKey(t)
	f.userPriv = userPriv
	f.options = AssemblyOptions{
		Env: "stage", Service: service, UserIssuer: "user", UserAudience: "finassist",
		UserKeys: providerFunc(func(context.Context) ([]byte, error) {
			return jwks(t, map[string]ed25519.PublicKey{"user-key": userPub}), nil
		}),
		Stage: StageKeyFiles{Issuer: "stage", SigningKeyFile: writeKey(t, f.servicePriv[service]), PublicKeysFile: writeFile(t, "services.json", stageJWKS(t, public))},
		Clock: func() time.Time { return *f.now }, Registerer: prometheus.NewRegistry(),
	}
	return f
}

func (f stageFixture) serviceToken(t *testing.T, signer, kid, sub string) string {
	t.Helper()
	now := *f.now
	return sign(t, f.servicePriv[signer], jwt.SigningMethodEdDSA, kid, jwt.RegisteredClaims{Issuer: "stage", Subject: sub, Audience: jwt.ClaimStrings{"finassist-internal"}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute))})
}

func TestUnitAssemblyStage(t *testing.T) {
	f := newStageFixture(t, "analytics")
	a, err := NewAssembly(f.options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	if len(a.caches) != 1 || a.transport != nil {
		t.Fatal("stage must not contact Kubernetes")
	}
	own, err := a.Token(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if caller, err := a.VerifyService(t.Context(), own); err != nil || caller != "analytics" {
		t.Fatal("own stage token rejected", caller, err)
	}
	if caller, err := a.VerifyService(t.Context(), f.serviceToken(t, "bank-bff", "bank-bff", "bank-bff")); err != nil || caller != "bank-bff" {
		t.Fatal(caller, err)
	}
	// A service key never vouches for another caller name.
	if caller, err := a.VerifyService(t.Context(), f.serviceToken(t, "bank-bff", "assistant", "assistant")); err == nil || caller != "" {
		t.Fatal("foreign key accepted")
	}
	if caller, err := a.VerifyService(t.Context(), f.serviceToken(t, "bank-bff", "bank-bff", "assistant")); err == nil || caller != "" {
		t.Fatal("kid/sub mismatch accepted")
	}
	user := sign(t, f.userPriv, jwt.SigningMethodEdDSA, "user-key", baseClaims(*f.now))
	if sub, err := a.VerifyUser(t.Context(), user); err != nil || sub != "user-1" {
		t.Fatal(sub, err)
	}
	// Stage service keys are not user keys.
	if _, err := a.VerifyUser(t.Context(), own); err == nil {
		t.Fatal("service token accepted as user token")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := a.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestUnitAssemblyStageFileFailures(t *testing.T) {
	_, other := testKey(t)
	for name, mutate := range map[string]func(*AssemblyOptions){
		"missing public keys":   func(o *AssemblyOptions) { o.Stage.PublicKeysFile = filepath.Join(t.TempDir(), "absent.json") },
		"oversized public keys": func(o *AssemblyOptions) { o.Stage.PublicKeysFile = writeFile(t, "big.json", make([]byte, maxJWKS+1)) },
		"broken public keys":    func(o *AssemblyOptions) { o.Stage.PublicKeysFile = writeFile(t, "bad.json", []byte("secret")) },
		"missing signing key":   func(o *AssemblyOptions) { o.Stage.SigningKeyFile = filepath.Join(t.TempDir(), "absent.pem") },
		"non-PEM signing key":   func(o *AssemblyOptions) { o.Stage.SigningKeyFile = writeFile(t, "key.pem", []byte("secret")) },
		"no file path":          func(o *AssemblyOptions) { o.Stage.PublicKeysFile = "" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newStageFixture(t, "assistant")
			mutate(&f.options)
			if _, err := NewAssembly(f.options); err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "/") {
				t.Fatal("bad stage file accepted or leaked", err)
			}
			if !metricsFree(f.options.Registerer) {
				t.Fatal("refused assembly left metrics registered")
			}
		})
	}
	// A valid key that is not this service's still loads: the pair is not cross-checked,
	// but the outgoing token then fails at every receiver, which is a deployment error.
	f := newStageFixture(t, "assistant")
	f.options.Stage.SigningKeyFile = writeKey(t, other)
	if _, err := NewAssembly(f.options); err != nil {
		t.Fatal(err)
	}
}

func TestUnitReadBounded(t *testing.T) {
	if _, err := readBounded("", 1); err == nil {
		t.Fatal("empty path accepted")
	}
	path := writeFile(t, "f", []byte("ab"))
	if b, err := readBounded(path, 2); err != nil || string(b) != "ab" {
		t.Fatal(b, err)
	}
	if _, err := readBounded(path, 1); err == nil {
		t.Fatal("oversized file accepted")
	}
}
