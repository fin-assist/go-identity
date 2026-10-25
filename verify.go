package identity

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"time"

	"github.com/fin-assist/contracts/gen/go/finerr"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
)

const maxToken = 16 << 10

const clockSkew = 5 * time.Second

// Observer receives only bounded library-defined kind/reason values. It must be
// safe for concurrent use. No token, user ID or untrusted caller is passed to it.
type Observer interface{ Reject(kind, reason string) }

// VerifyOptions pins issuer, audience and clock. All are required. Observer is
// optional. JWT algorithm policy is fixed by the constructor, never by a token.
// iat/nbf tolerate five seconds of clock skew; exp remains a strict boundary.
type VerifyOptions struct {
	Issuer, Audience string
	Clock            func() time.Time
	Observer         Observer
}

type claims struct {
	jwt.RegisteredClaims
	Kubernetes struct {
		Namespace      string `json:"namespace"`
		ServiceAccount struct {
			Name string `json:"name"`
		} `json:"serviceaccount"`
	} `json:"kubernetes.io"`
}

type verifier struct {
	options    VerifyOptions
	algorithms []string
	key        func(context.Context, string) (verificationKey, error)
}

func newVerifier(o VerifyOptions, algorithms []string, key func(context.Context, string) (verificationKey, error)) (verifier, error) {
	if strings.TrimSpace(o.Issuer) == "" || strings.TrimSpace(o.Audience) == "" || o.Clock == nil {
		return verifier{}, errors.New("identity: issuer, audience and clock are required")
	}
	return verifier{o, algorithms, key}, nil
}

// errInvalidToken is the verdict for a token that is malformed, forged,
// expired, foreign or signed with a key absent from a fresh snapshot.
var errInvalidToken = errors.New("identity: invalid token")

// parse returns the verified claims and kid, or one of errInvalidToken,
// errKeysUnavailable and a context error. Only errInvalidToken judges the token.
func (v verifier) parse(ctx context.Context, raw, kind string) (*claims, string, error) {
	reason := "invalid"
	if len(raw) == 0 || len(raw) > maxToken {
		v.reject(kind, reason)
		return nil, "", errInvalidToken
	}
	var keyErr error
	c := new(claims)
	t, err := jwt.ParseWithClaims(raw, c, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" || len(kid) > 256 {
			return nil, errors.New("identity: missing key ID")
		}
		// No critical extensions are implemented, nor any token-supplied key URL.
		if _, ok := t.Header["crit"]; ok {
			return nil, errors.New("identity: unsupported critical header")
		}
		k, err := v.key(ctx, kid)
		if err != nil {
			keyErr = err
			return nil, err
		}
		if k.algorithm != t.Method.Alg() {
			return nil, errors.New("identity: wrong key algorithm")
		}
		return k.public, nil
	}, jwt.WithValidMethods(v.algorithms), jwt.WithExpirationRequired(), jwt.WithIssuer(v.options.Issuer), jwt.WithAudience(v.options.Audience), jwt.WithTimeFunc(v.options.Clock), jwt.WithIssuedAt(), jwt.WithLeeway(clockSkew))
	switch {
	case keyErr == nil:
	case errors.Is(keyErr, context.Canceled) || errors.Is(keyErr, context.DeadlineExceeded):
		// The caller went away; this is neither a verdict nor a key outage.
		return nil, "", keyErr
	case errors.Is(keyErr, errUnknownKey):
		reason = "unknown_key"
	default:
		// No fresh trusted snapshot: the token was not judged at all.
		v.reject(kind, "key_unavailable")
		return nil, "", errKeysUnavailable
	}
	// Apply skew only to iat/nbf, never extend the access/service expiration.
	if err == nil && t.Valid && !v.options.Clock().Before(c.ExpiresAt.Time) {
		err = jwt.ErrTokenExpired
	}
	if err == nil && t.Valid && strings.TrimSpace(c.Subject) != "" && len(c.Subject) <= 256 {
		kid, _ := t.Header["kid"].(string)
		return c, kid, nil
	}
	if err != nil && keyErr == nil {
		switch {
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			reason = "signature"
		case errors.Is(err, jwt.ErrTokenExpired):
			reason = "expired"
		case errors.Is(err, jwt.ErrTokenInvalidAudience):
			reason = "audience"
		case errors.Is(err, jwt.ErrTokenInvalidIssuer):
			reason = "issuer"
		}
	}
	v.reject(kind, reason)
	return nil, "", errInvalidToken
}

// verifierStatus maps a parse error that is not a verdict on the token to a bare
// retryable gRPC status; it returns nil for errInvalidToken.
func verifierStatus(err error) error {
	switch {
	case errors.Is(err, errKeysUnavailable):
		return internalStatus(codes.Unavailable)
	case errors.Is(err, context.DeadlineExceeded):
		return internalStatus(codes.DeadlineExceeded)
	case errors.Is(err, context.Canceled):
		return internalStatus(codes.Canceled)
	}
	return nil
}

func (v verifier) reject(kind, reason string) {
	if v.options.Observer != nil {
		v.options.Observer.Reject(kind, reason)
	}
}

// UserVerifier verifies Ed25519 or ES256 access tokens. It is concurrency safe.
type UserVerifier struct{ verifier }

// NewUserVerifier requires trusted user keys. Expired and malformed access tokens
// both become finerr.InvalidToken (TOKEN_EXPIRED is a registration-token error).
// When no fresh key snapshot can be obtained, VerifyUser returns a bare
// UNAVAILABLE instead: a key outage must not log users out.
func NewUserVerifier(keys *KeyCache, o VerifyOptions) (*UserVerifier, error) {
	if keys == nil {
		return nil, errors.New("identity: user keys required")
	}
	v, err := newVerifier(o, []string{"EdDSA", "ES256"}, keys.key)
	if err != nil {
		return nil, err
	}
	return &UserVerifier{v}, nil
}

// VerifyUser returns a verified sub, finerr.InvalidToken() for a rejected token,
// or a bare gRPC status without details when the token could not be judged:
// UNAVAILABLE (no fresh trusted keys), CANCELED or DEADLINE_EXCEEDED (ctx ended).
func (v *UserVerifier) VerifyUser(ctx context.Context, token string) (string, error) {
	c, _, err := v.parse(ctx, token, "user")
	if err != nil {
		if s := verifierStatus(err); s != nil {
			return "", s
		}
		return "", finerr.InvalidToken()
	}
	return c.Subject, nil
}

// KubernetesVerifier verifies projected tokens, including the namespace and the
// agreement between sub and kubernetes.io.serviceaccount.name. Concurrency safe.
type KubernetesVerifier struct {
	verifier
	namespace string
}

// NewKubernetesVerifier requires the pinned issuer, audience finassist-internal,
// and namespace finassist (or an explicitly isolated deployment namespace).
func NewKubernetesVerifier(keys *KeyCache, o VerifyOptions, namespace string) (*KubernetesVerifier, error) {
	if keys == nil || !serviceName(namespace) || o.Audience != "finassist-internal" {
		return nil, errors.New("identity: invalid Kubernetes options")
	}
	v, err := newVerifier(o, []string{"RS256", "ES256", "EdDSA"}, keys.key)
	if err != nil {
		return nil, err
	}
	return &KubernetesVerifier{v, namespace}, nil
}

// VerifyService returns a verified service name or a sanitized internal error.
// A token that could not be judged yields a bare UNAVAILABLE, CANCELED or
// DEADLINE_EXCEEDED status (see VerifyUser); Server passes it on unchanged.
func (v *KubernetesVerifier) VerifyService(ctx context.Context, token string) (string, error) {
	c, _, err := v.parse(ctx, token, "service")
	if err != nil {
		if s := verifierStatus(err); s != nil {
			return "", s
		}
		return "", err
	}
	name := c.Kubernetes.ServiceAccount.Name
	if !serviceName(name) || c.Kubernetes.Namespace != v.namespace || c.Subject != "system:serviceaccount:"+v.namespace+":"+name {
		v.reject("service", "invalid")
		return "", errors.New("identity: invalid service identity")
	}
	return name, nil
}

// StageVerifier verifies short stage JWTs. Each public key is bound to its
// service name: a service cannot sign a token naming a different caller.
type StageVerifier struct{ verifier }

// NewStageVerifier accepts only env=stage or dev, Ed25519 public keys indexed by
// service name, and audience finassist-internal. It refuses prod and unknown envs.
// Keys are copied; a new verifier is needed to replace the configured key set.
func NewStageVerifier(env string, o VerifyOptions, keys map[string]ed25519.PublicKey) (*StageVerifier, error) {
	if (env != "stage" && env != "dev") || o.Audience != "finassist-internal" || len(keys) == 0 || len(keys) > 64 {
		return nil, errors.New("identity: invalid stage verifier options")
	}
	copyKeys := make(map[string]ed25519.PublicKey, len(keys))
	for name, key := range keys {
		if !serviceName(name) || len(key) != ed25519.PublicKeySize {
			return nil, errors.New("identity: invalid stage public key")
		}
		copyKeys[name] = append(ed25519.PublicKey(nil), key...)
	}
	v, err := newVerifier(o, []string{"EdDSA"}, func(_ context.Context, kid string) (verificationKey, error) {
		k, ok := copyKeys[kid]
		if !ok {
			return verificationKey{}, errUnknownKey
		}
		return verificationKey{"EdDSA", k}, nil
	})
	if err != nil {
		return nil, err
	}
	return &StageVerifier{v}, nil
}

// VerifyService returns the key-bound caller or a sanitized internal error.
// Stage tokens must have iat, a lifetime of at most five minutes, and kid=sub.
func (v *StageVerifier) VerifyService(ctx context.Context, token string) (string, error) {
	c, kid, err := v.parse(ctx, token, "service")
	if err != nil {
		if s := verifierStatus(err); s != nil {
			return "", s
		}
		return "", err
	}
	if c.Subject != kid || c.IssuedAt == nil || c.ExpiresAt.Sub(c.IssuedAt.Time) <= 0 || c.ExpiresAt.Sub(c.IssuedAt.Time) > 5*time.Minute {
		v.reject("service", "invalid")
		return "", errors.New("identity: invalid stage identity")
	}
	return c.Subject, nil
}

func serviceName(name string) bool {
	if len(name) == 0 || len(name) > 63 || name[0] == '-' || name[len(name)-1] == '-' {
		return false
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}
