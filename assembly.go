package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	userv1 "github.com/fin-assist/contracts/gen/go/finassist/user/v1"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
)

// Defaults of KubernetesOptions; they match the AUTH_KUBERNETES_* defaults the
// services document.
const (
	defaultKubernetesIssuer       = "https://kubernetes.default.svc.cluster.local"
	defaultKubernetesJWKSURL      = "https://kubernetes.default.svc/openid/v1/jwks"
	defaultKubernetesCAFile       = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	defaultKubernetesAPITokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // A file path, not a credential.
	defaultKubernetesNamespace    = "finassist"
)

// Maximum snapshot ages of the two key caches (see NewKeyCache).
const (
	userKeysMaxAge    = 10 * time.Minute
	serviceKeysMaxAge = time.Hour
)

// The CA bundle is trusted deployment configuration, still bounded like other files.
const maxCAFile = 1 << 20

// AssemblyOptions configures NewAssembly. The service maps its own configuration
// to these fields; the library never reads the environment.
type AssemblyOptions struct {
	// Env is the verified deployment environment of the service: "prod" selects
	// Kubernetes ServiceAccount tokens, "stage" selects short JWTs signed with
	// file keys. Empty, "dev" and any other value are refused: dev-only verifiers
	// remain a separate service decision reachable only with ENV=dev.
	Env string
	// Service is this service's name (its ServiceAccount). In stage it is the
	// kid and sub of the outgoing tokens.
	Service string
	// UserIssuer and UserAudience pin user access JWTs (AUTH_USER_ISSUER,
	// AUTH_USER_AUDIENCE); both are required.
	UserIssuer, UserAudience string
	// DialUser opens the connection to the user service used for GetSigningKeys.
	// It receives the outgoing token source of this assembly and must install it
	// on every call (go-grpc client.Dial with Tokens set to it, retrying only
	// finassist.user.v1.UserInternalService/GetSigningKeys). The assembly owns
	// the returned connection and closes it in Close. Exactly one of DialUser
	// and UserKeys is set.
	DialUser func(TokenSource) (*grpc.ClientConn, error)
	// UserKeys replaces DialUser in the user service itself, which publishes
	// its own keys through a local provider instead of calling its own RPC.
	UserKeys JWKSProvider
	// Kubernetes configures prod. Its empty fields take documented defaults.
	Kubernetes KubernetesOptions
	// Stage configures stage. Setting any of its fields in prod is refused.
	Stage StageKeyFiles
	// Clock is "now" of every verifier, key cache and stage token. Required.
	Clock func() time.Time
	// Registerer is the service metrics registry. Required.
	Registerer prometheus.Registerer
}

// KubernetesOptions are the prod settings. An empty field takes its default.
type KubernetesOptions struct {
	// TokenFile is the projected token of this service with audience
	// finassist-internal (SERVICE_TOKEN_FILE). Required, no default; it must
	// differ from APITokenFile.
	TokenFile string
	// Issuer of ServiceAccount tokens (AUTH_KUBERNETES_ISSUER), default
	// https://kubernetes.default.svc.cluster.local.
	Issuer string
	// JWKSURL is the pinned HTTPS key endpoint (AUTH_KUBERNETES_JWKS_URL),
	// default https://kubernetes.default.svc/openid/v1/jwks.
	JWKSURL string
	// CAFile is the PEM bundle trusted for JWKSURL (AUTH_KUBERNETES_CA_FILE),
	// default /var/run/secrets/kubernetes.io/serviceaccount/ca.crt.
	CAFile string
	// APITokenFile is the API-server-audience token presented to JWKSURL
	// (AUTH_KUBERNETES_API_TOKEN_FILE), default
	// /var/run/secrets/kubernetes.io/serviceaccount/token.
	APITokenFile string
	// Namespace of trusted callers (AUTH_KUBERNETES_NAMESPACE), default finassist.
	Namespace string
}

// StageKeyFiles are the stage settings; all are required in stage.
type StageKeyFiles struct {
	// Issuer shared by every stage service (AUTH_STAGE_ISSUER).
	Issuer string
	// SigningKeyFile is this service's PKCS#8 PEM Ed25519 private key
	// (AUTH_STAGE_SIGNING_KEY_FILE), read once at construction.
	SigningKeyFile string
	// PublicKeysFile is a JWKS of stage service keys (AUTH_STAGE_PUBLIC_KEYS_FILE):
	// OKP Ed25519 only, kid = service name, at most 64 keys and 1 MiB. It is
	// separate from user keys and read once at construction.
	PublicKeysFile string
}

func (s StageKeyFiles) empty() bool {
	return s.Issuer == "" && s.SigningKeyFile == "" && s.PublicKeysFile == ""
}

// Assembly is the identity a service needs: incoming service and user token
// verification and the outgoing service token, with the user key set from
// user.GetSigningKeys refreshed in the background. It implements the verifier
// and token-source interfaces of go-grpc server/client and of this package.
// It is safe for concurrent use.
type Assembly struct {
	services  ServiceChecker
	users     *UserVerifier
	tokens    TokenSource
	caches    []*KeyCache
	conn      *grpc.ClientConn
	transport *http.Transport
	closeOnce sync.Once
	closeErr  error
}

// NewAssembly validates options, reads the configured files and builds the
// verifiers. It registers finassist_identity_rejected_total and
// finassist_identity_jwks_skipped_keys in Registerer. No key is fetched and no
// goroutine is started: the service runs Run as a background job and calls
// Close at shutdown. Errors contain no paths, tokens or key material; an error
// leaves nothing registered or open.
func NewAssembly(o AssemblyOptions) (*Assembly, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	a := &Assembly{}
	var serviceProvider JWKSProvider
	var stageKeys map[string]ed25519.PublicKey
	switch o.Env {
	case envProd:
		k := o.Kubernetes.withDefaults()
		tokens, err := NewProjectedSource(k.TokenFile)
		if err != nil {
			return nil, err
		}
		apiTokens, err := NewProjectedSource(k.APITokenFile)
		if err != nil {
			return nil, err
		}
		transport, err := kubernetesTransport(k.CAFile)
		if err != nil {
			return nil, err
		}
		provider, err := NewHTTPKeys(&http.Client{Transport: transport, Timeout: 5 * time.Second}, k.JWKSURL, apiTokens)
		if err != nil {
			transport.CloseIdleConnections()
			return nil, err
		}
		a.tokens, a.transport, serviceProvider = tokens, transport, provider
	case envStage:
		keys, err := loadStagePublicKeys(o.Stage.PublicKeysFile)
		if err != nil {
			return nil, err
		}
		source, err := NewStageSource(envStage, StageOptions{KeyFile: o.Stage.SigningKeyFile, Caller: o.Service, Issuer: o.Stage.Issuer, Clock: o.Clock})
		if err != nil {
			return nil, err
		}
		a.tokens, stageKeys = source, keys
	}
	userProvider := o.UserKeys
	if o.DialUser != nil {
		conn, err := o.DialUser(a.tokens)
		if err != nil || conn == nil {
			if conn != nil {
				_ = conn.Close()
			}
			_ = a.release()
			return nil, errors.New("identity: user connection configuration failed")
		}
		a.conn = conn
		userProvider = UserKeys{Client: userv1.NewUserInternalServiceClient(conn)}
	}
	metrics, err := NewMetrics(o.Registerer)
	if err != nil {
		_ = a.release()
		return nil, err
	}
	if err := a.build(o, metrics, userProvider, serviceProvider, stageKeys); err != nil {
		o.Registerer.Unregister(metrics.rejected)
		o.Registerer.Unregister(metrics.skipped)
		_ = a.release()
		return nil, err
	}
	return a, nil
}

func (a *Assembly) build(o AssemblyOptions, metrics *Metrics, userProvider, serviceProvider JWKSProvider, stageKeys map[string]ed25519.PublicKey) error {
	userCache, err := NewObservedKeyCache(userProvider, o.Clock, userKeysMaxAge, "user", metrics)
	if err != nil {
		return err
	}
	a.users, err = NewUserVerifier(userCache, VerifyOptions{Issuer: o.UserIssuer, Audience: o.UserAudience, Clock: o.Clock, Observer: metrics})
	if err != nil {
		return err
	}
	a.caches = []*KeyCache{userCache}
	if o.Env == envStage {
		a.services, err = NewStageVerifier(envStage, VerifyOptions{Issuer: o.Stage.Issuer, Audience: serviceAudience, Clock: o.Clock, Observer: metrics}, stageKeys)
		return err
	}
	k := o.Kubernetes.withDefaults()
	serviceCache, err := NewObservedKeyCache(serviceProvider, o.Clock, serviceKeysMaxAge, "service", metrics)
	if err != nil {
		return err
	}
	a.services, err = NewKubernetesVerifier(serviceCache, VerifyOptions{Issuer: k.Issuer, Audience: serviceAudience, Clock: o.Clock, Observer: metrics}, k.Namespace)
	if err != nil {
		return err
	}
	a.caches = append(a.caches, serviceCache)
	return nil
}

const (
	envProd         = "prod"
	envStage        = "stage"
	serviceAudience = "finassist-internal"
)

func (o AssemblyOptions) validate() error {
	if o.Env != envProd && o.Env != envStage {
		return errors.New("identity: assembly requires env prod or stage")
	}
	if !serviceName(o.Service) || o.Clock == nil || o.Registerer == nil {
		return errors.New("identity: service name, clock and registerer are required")
	}
	if strings.TrimSpace(o.UserIssuer) == "" || strings.TrimSpace(o.UserAudience) == "" {
		return errors.New("identity: user issuer and audience are required")
	}
	if (o.DialUser == nil) == (o.UserKeys == nil) {
		return errors.New("identity: exactly one of DialUser and UserKeys is required")
	}
	if o.Env == envStage {
		if strings.TrimSpace(o.Stage.Issuer) == "" || o.Stage.SigningKeyFile == "" || o.Stage.PublicKeysFile == "" {
			return errors.New("identity: stage issuer and key files are required")
		}
		return nil
	}
	if !o.Stage.empty() {
		return errors.New("identity: stage keys are not allowed in prod")
	}
	k := o.Kubernetes.withDefaults()
	// Compare canonical paths: "…/serviceaccount//token" is the API token too.
	if k.TokenFile == "" || filepath.Clean(k.TokenFile) == filepath.Clean(k.APITokenFile) {
		return errors.New("identity: separate service and API token files are required")
	}
	if strings.TrimSpace(k.Issuer) == "" || !serviceName(k.Namespace) {
		return errors.New("identity: invalid Kubernetes issuer or namespace")
	}
	return nil
}

func (k KubernetesOptions) withDefaults() KubernetesOptions {
	if k.Issuer == "" {
		k.Issuer = defaultKubernetesIssuer
	}
	if k.JWKSURL == "" {
		k.JWKSURL = defaultKubernetesJWKSURL
	}
	if k.CAFile == "" {
		k.CAFile = defaultKubernetesCAFile
	}
	if k.APITokenFile == "" {
		k.APITokenFile = defaultKubernetesAPITokenFile
	}
	if k.Namespace == "" {
		k.Namespace = defaultKubernetesNamespace
	}
	return k
}

// kubernetesTransport trusts only the configured CA bundle. Proxy is nil, so no
// proxy environment variable is consulted.
func kubernetesTransport(caFile string) (*http.Transport, error) {
	pem, err := readBounded(caFile, maxCAFile)
	if err != nil {
		return nil, errors.New("identity: Kubernetes CA file unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("identity: invalid Kubernetes CA file")
	}
	return &http.Transport{
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}, nil
}

// loadStagePublicKeys reads a stage JWKS whose every key is an Ed25519 key of
// one service (kid = service name). An unsupported or foreign key fails the
// whole file: stage configuration is trusted and must be exact.
func loadStagePublicKeys(path string) (map[string]ed25519.PublicKey, error) {
	data, err := readBounded(path, maxJWKS)
	if err != nil {
		return nil, errors.New("identity: stage public keys unavailable")
	}
	return parseStagePublicKeys(data)
}

func parseStagePublicKeys(data []byte) (map[string]ed25519.PublicKey, error) {
	invalid := errors.New("identity: invalid stage public keys")
	set, err := parseJWKS(data)
	if err != nil {
		return nil, invalid
	}
	for _, count := range set.skipped {
		if count > 0 {
			return nil, invalid
		}
	}
	keys := make(map[string]ed25519.PublicKey, len(set.byKID))
	for kid, key := range set.byKID {
		public, ok := key.public.(ed25519.PublicKey)
		if !ok || key.algorithm != "EdDSA" || !serviceName(kid) {
			return nil, invalid
		}
		keys[kid] = public
	}
	return keys, nil
}

// readBounded reads a regular file of at most limit bytes.
func readBounded(path string, limit int64) ([]byte, error) {
	if path == "" {
		return nil, errors.New("identity: file required")
	}
	f, err := os.Open(path) //nolint:gosec // Trusted deployment configuration, never request input.
	if err != nil {
		return nil, errors.New("identity: file unavailable")
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("identity: invalid file")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("identity: invalid file")
	}
	return b, nil
}

// VerifyService returns the verified caller of an incoming service token: a
// Kubernetes ServiceAccount in prod, a key-bound stage service in stage. Errors
// are those of KubernetesVerifier.VerifyService or StageVerifier.VerifyService.
func (a *Assembly) VerifyService(ctx context.Context, token string) (string, error) {
	return a.services.VerifyService(ctx, token)
}

// VerifyUser returns the verified sub of a user access token; errors are those
// of UserVerifier.VerifyUser.
func (a *Assembly) VerifyUser(ctx context.Context, token string) (string, error) {
	return a.users.VerifyUser(ctx, token)
}

// Token returns this service's outgoing token: the projected finassist-internal
// file in prod, a freshly signed short JWT in stage.
func (a *Assembly) Token(ctx context.Context) (string, error) {
	return a.tokens.Token(ctx)
}

// Run refreshes every key cache in the background (see KeyCache.Run): user keys
// in both environments, Kubernetes keys in prod. Before Run, keys are fetched
// lazily on the first request. The service owns this job; it returns ctx.Err()
// after every refresh loop has stopped.
func (a *Assembly) Run(ctx context.Context) error {
	var loops sync.WaitGroup
	for _, cache := range a.caches {
		loops.Go(func() { _ = cache.Run(ctx) })
	}
	loops.Wait()
	return ctx.Err()
}

// Close releases the user connection opened by DialUser and idle connections of
// the Kubernetes JWKS client. Call it after Run has returned; repeated calls
// return the first result.
func (a *Assembly) Close() error {
	a.closeOnce.Do(func() { a.closeErr = a.release() })
	return a.closeErr
}

func (a *Assembly) release() error {
	var err error
	if a.conn != nil && a.conn.Close() != nil {
		err = errors.New("identity: user connection close failed")
	}
	if a.transport != nil {
		a.transport.CloseIdleConnections()
	}
	return err
}
