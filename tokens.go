package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenSource supplies a raw service bearer token. Implementations must be
// concurrency safe and must not include token material in errors.
type TokenSource interface {
	Token(context.Context) (string, error)
}

// ProjectedSource reads kubelet's rotating projected file. Safe for concurrent use.
// A symlink target replacement invalidates the cache even when mtime is unchanged.
type ProjectedSource struct {
	path  string
	mu    sync.Mutex
	info  os.FileInfo
	token string
}

// NewProjectedSource pins the local token path; it does not read the environment.
func NewProjectedSource(path string) (*ProjectedSource, error) {
	if path == "" {
		return nil, errors.New("identity: token path required")
	}
	return &ProjectedSource{path: path}, nil
}

// Token stats and reads the current file, caching by identity, mtime and size.
// Deleted/unreadable/oversized files fail closed, without returning a stale token.
func (s *ProjectedSource) Token(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(s.path)
	if err != nil {
		return "", errors.New("identity: service token unavailable")
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxToken+2 {
		return "", errors.New("identity: invalid token file")
	}
	if s.info != nil && os.SameFile(s.info, info) && s.info.ModTime().Equal(info.ModTime()) && s.info.Size() == info.Size() {
		return s.token, nil
	}
	b, err := io.ReadAll(io.LimitReader(f, maxToken+3))
	token := strings.TrimSpace(string(b))
	if err != nil || len(token) == 0 || len(token) > maxToken || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("identity: invalid token file")
	}
	s.info, s.token = info, token
	return token, nil
}

// StageOptions describes a stage service's Ed25519 PKCS#8 PEM key file. Clock,
// issuer and caller are required. TTL defaults to one minute, maximum five minutes.
type StageOptions struct {
	KeyFile, Caller, Issuer string
	Clock                   func() time.Time
	TTL                     time.Duration
}

// StageSource signs short service JWTs. Safe for concurrent use. It loads its own
// key once at construction; restart the service to install a rotated private key.
type StageSource struct {
	options StageOptions
	key     ed25519.PrivateKey
	mu      sync.Mutex
	token   string
	expires time.Time
}

// NewStageSource refuses prod/unknown environments and reads a bounded PKCS#8
// Ed25519 key. Errors deliberately exclude paths, PEM data and parser diagnostics.
func NewStageSource(env string, o StageOptions) (*StageSource, error) {
	if o.TTL == 0 {
		o.TTL = time.Minute
	}
	if (env != "stage" && env != "dev") || !serviceName(o.Caller) || o.Issuer == "" || o.Clock == nil || o.TTL < time.Second || o.TTL > 5*time.Minute || o.KeyFile == "" {
		return nil, errors.New("identity: invalid stage source options")
	}
	f, err := os.Open(o.KeyFile)
	if err != nil {
		return nil, errors.New("identity: stage signing key unavailable")
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(b) > 8192 {
		return nil, errors.New("identity: invalid stage signing key")
	}
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("identity: invalid stage signing key")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := k.(ed25519.PrivateKey)
	if err != nil || !ok {
		return nil, errors.New("identity: Ed25519 stage signing key required")
	}
	return &StageSource{options: o, key: key}, nil
}

// Token returns a signed JWT (kid=sub=caller, aud=finassist-internal), refreshing
// it before the last 20% of its lifetime. A cancelled context returns no token.
func (s *StageSource) Token(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.options.Clock()
	if s.token != "" && now.Before(s.expires.Add(-s.options.TTL/5)) {
		return s.token, nil
	}
	exp := jwt.NewNumericDate(now.Add(s.options.TTL))
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.RegisteredClaims{Subject: s.options.Caller, Issuer: s.options.Issuer, Audience: jwt.ClaimStrings{"finassist-internal"}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: exp})
	t.Header["kid"] = s.options.Caller
	raw, err := t.SignedString(s.key)
	if err != nil {
		return "", errors.New("identity: stage signing failed")
	}
	s.token, s.expires = raw, exp.Time
	return raw, nil
}
