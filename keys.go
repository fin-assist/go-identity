package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"slices"
	"sync"
	"time"
)

const maxJWKS = 1 << 20

// Check more often than the refresh rate limit so scheduler jitter cannot skip
// a whole minute of retries at the limit boundary.
const refreshCheckPeriod = 30 * time.Second

// JWKSProvider fetches trusted keys. Implementations must honour cancellation and
// must not use a URL or key supplied by a token. Errors are never sent to callers.
type JWKSProvider interface {
	JWKS(context.Context) ([]byte, error)
}

// errKeysUnavailable means no fresh trusted snapshot could be obtained: the
// provider failed, returned an invalid set, or the last attempt failed within the
// refresh rate limit. It says nothing about the token being verified.
var errKeysUnavailable = errors.New("identity: keys unavailable")

// errUnknownKey means a fresh trusted snapshot has no key with the token's kid.
var errUnknownKey = errors.New("identity: unknown key ID")

type verificationKey struct {
	algorithm string
	public    crypto.PublicKey
}

// KeyCache caches an immutable JWKS snapshot. It is safe for concurrent use.
// Refreshes, including failed ones and unknown kids, are limited to once a minute.
// A snapshot older than its interval is not used after a failed refresh.
// Lookups distinguish an unavailable snapshot from an unknown kid in a fresh one.
type KeyCache struct {
	provider           JWKSProvider
	clock              func() time.Time
	interval           time.Duration
	gate               chan struct{}
	mu                 sync.RWMutex
	keys               map[string]verificationKey
	updated, attempted time.Time
	hasAttempt         bool
	kind               string
	observer           KeyObserver
}

// KeyObserver receives, after each installed snapshot, the number of JWKs skipped
// as unsupported for every bounded reason (kty, crv, alg, use, key_ops, size),
// zero included. Calls for one cache are serialized. It must not block.
type KeyObserver interface {
	SkippedKeys(kind, reason string, count int)
}

// NewKeyCache requires a provider, an injected clock and a maximum snapshot age of at least
// two minutes (10 minutes for user keys, one hour for Kubernetes keys).
func NewKeyCache(provider JWKSProvider, clock func() time.Time, interval time.Duration) (*KeyCache, error) {
	if provider == nil || clock == nil || interval < 2*time.Minute {
		return nil, errors.New("identity: invalid key cache options")
	}
	return &KeyCache{provider: provider, clock: clock, interval: interval, gate: make(chan struct{}, 1)}, nil
}

// key returns the key for kid, the context error, errKeysUnavailable when no
// fresh snapshot is available, or errUnknownKey when a fresh one lacks kid.
func (c *KeyCache) key(ctx context.Context, kid string) (verificationKey, error) {
	if err := ctx.Err(); err != nil {
		return verificationKey{}, err
	}
	c.mu.RLock()
	k, ok := c.keys[kid]
	fresh := c.keys != nil && c.clock().Sub(c.updated) < c.interval
	c.mu.RUnlock()
	if ok && fresh {
		return k, nil
	}
	// A failed refresh is not a verdict by itself: a fresh snapshot still judges
	// the kid below, so a random kid cannot turn a key outage into UNAVAILABLE.
	_ = c.refresh(ctx)
	if err := ctx.Err(); err != nil {
		return verificationKey{}, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.keys == nil || c.clock().Sub(c.updated) >= c.interval {
		return verificationKey{}, errKeysUnavailable
	}
	k, ok = c.keys[kid]
	if !ok {
		return verificationKey{}, errUnknownKey
	}
	return k, nil
}

// refresh loads a new snapshot at most once a minute. It returns the context
// error, errKeysUnavailable when this attempt failed, or nil (including when the
// rate limit skipped the attempt). Callers judge the stored snapshot afterwards.
func (c *KeyCache) refresh(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case c.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-c.gate }()
	if err := ctx.Err(); err != nil {
		return err
	}
	now := c.clock()
	if c.hasAttempt && now.Sub(c.attempted) < time.Minute {
		return nil
	}
	c.attempted, c.hasAttempt = now, true
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	data, err := c.provider.JWKS(ctx)
	if err != nil {
		return errKeysUnavailable
	}
	keys, err := parseJWKS(data)
	if err != nil {
		return errKeysUnavailable
	}
	c.mu.Lock()
	c.keys, c.updated = keys.byKID, c.clock()
	c.mu.Unlock()
	c.observeSkipped(keys.skipped)
	return nil
}

// Run proactively refreshes a snapshot at half its maximum age, checking every
// 30 seconds. Failed loads become eligible after one minute and retry on the next
// eligible tick. The old snapshot is usable only within its maximum age. The
// service owns this job; cancellation waits at most five seconds for an already
// started shared fetch. The return value is ctx.Err().
func (c *KeyCache) Run(ctx context.Context) error {
	ticker := time.NewTicker(refreshCheckPeriod)
	defer ticker.Stop()
	return c.run(ctx, ticker.C)
}

func (c *KeyCache) refreshIfDue(ctx context.Context) {
	c.mu.RLock()
	due := c.keys == nil || c.clock().Sub(c.updated) >= c.interval/2
	c.mu.RUnlock()
	if due {
		_ = c.refresh(ctx)
	}
}

func (c *KeyCache) run(ctx context.Context, ticks <-chan time.Time) error {
	c.refreshIfDue(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticks:
			c.refreshIfDue(ctx)
		}
	}
}

// NewObservedKeyCache is NewKeyCache that also reports skipped JWKs of each
// installed snapshot to observer (for example *Metrics). kind is "user" for user
// keys or "service" for Kubernetes keys; observer is required.
func NewObservedKeyCache(provider JWKSProvider, clock func() time.Time, interval time.Duration, kind string, observer KeyObserver) (*KeyCache, error) {
	if (kind != "user" && kind != "service") || observer == nil {
		return nil, errors.New("identity: invalid key cache observer")
	}
	c, err := NewKeyCache(provider, clock, interval)
	if err != nil {
		return nil, err
	}
	c.kind, c.observer = kind, observer
	return c, nil
}

// observeSkipped reports a newly installed snapshot. It runs under the refresh
// gate, so reports of one cache never interleave.
func (c *KeyCache) observeSkipped(skipped map[string]int) {
	if c.observer == nil {
		return
	}
	for _, reason := range skipReasons() {
		c.observer.SkippedKeys(c.kind, reason, skipped[reason])
	}
}

// Reasons for skipping a JWK whose type or purpose the library does not support.
// They are bounded metric label values; a skipped key's kid is never reported.
const (
	skipUse    = "use"
	skipKeyOps = "key_ops"
	skipKty    = "kty"
	skipCrv    = "crv"
	skipAlg    = "alg"
	skipSize   = "size"
)

// skipReasons lists every skip reason, so an observer can reset reasons that
// disappeared from the new snapshot.
func skipReasons() []string {
	return []string{skipKty, skipCrv, skipAlg, skipUse, skipKeyOps, skipSize}
}

// jwk holds the members of a JSON Web Key that the library inspects.
type jwk struct {
	Kty, Kid, Alg, Use, Crv, X, Y, N, E string
	KeyOps                              []string `json:"key_ops"`
}

// parsedJWKS is a validated snapshot: the supported keys by kid and the number
// of unsupported JWKs skipped for each reason.
type parsedJWKS struct {
	byKID   map[string]verificationKey
	skipped map[string]int
}

// parseJWKS skips a JWK whose type or purpose is not supported (RFC 7517,
// section 5) and rejects the whole set for clearly broken data: invalid JSON,
// size or count limits, a missing kty, a missing or duplicate kid (counted over
// skipped keys too), bad material of a supported key type, a weak RSA key, or no
// supported key at all. A token whose kid belongs to a skipped key is rejected as
// one with an unknown kid, never verified.
func parseJWKS(data []byte) (parsedJWKS, error) {
	invalid := errors.New("identity: invalid JWKS")
	if len(data) > maxJWKS {
		return parsedJWKS{}, invalid
	}
	var set struct{ Keys []jwk }
	if json.Unmarshal(data, &set) != nil || len(set.Keys) == 0 || len(set.Keys) > 64 {
		return parsedJWKS{}, invalid
	}
	result := parsedJWKS{byKID: make(map[string]verificationKey, len(set.Keys)), skipped: map[string]int{}}
	seen := make(map[string]struct{}, len(set.Keys))
	for _, j := range set.Keys {
		// kty is REQUIRED by RFC 7517 (4.1), like the kid this library relies on:
		// a key without it is broken data, not an unsupported type.
		if j.Kid == "" || len(j.Kid) > 256 || j.Kty == "" {
			return parsedJWKS{}, invalid
		}
		// A kid must name one key in the published set whatever this library
		// supports; otherwise a later version could resolve it differently.
		if _, exists := seen[j.Kid]; exists {
			return parsedJWKS{}, invalid
		}
		seen[j.Kid] = struct{}{}
		key, skip, err := parseJWK(j)
		if err != nil {
			return parsedJWKS{}, invalid
		}
		if skip != "" {
			result.skipped[skip]++
			continue
		}
		result.byKID[j.Kid] = key
	}
	if len(result.byKID) == 0 {
		return parsedJWKS{}, invalid
	}
	return result, nil
}

// unsupportedJWK returns the skip reason for a key of an unsupported type or
// purpose, or "" when the key must be parsed. Purpose is checked before type.
func unsupportedJWK(j jwk) string {
	if j.Use != "" && j.Use != "sig" {
		return skipUse
	}
	if len(j.KeyOps) > 0 && !slices.Contains(j.KeyOps, "verify") {
		return skipKeyOps
	}
	switch j.Kty {
	case "OKP":
		if j.Crv != "Ed25519" {
			return skipCrv
		}
		if j.Alg != "" && j.Alg != "EdDSA" {
			return skipAlg
		}
	case "EC":
		if j.Crv != "P-256" {
			return skipCrv
		}
		if j.Alg != "" && j.Alg != "ES256" {
			return skipAlg
		}
	case "RSA":
		if j.Alg != "" && j.Alg != "RS256" {
			return skipAlg
		}
	default:
		return skipKty
	}
	return ""
}

// parseJWK returns a verification key, a skip reason for an unsupported key, or
// an error for broken material of a supported key type.
func parseJWK(j jwk) (verificationKey, string, error) {
	if skip := unsupportedJWK(j); skip != "" {
		return verificationKey{}, skip, nil
	}
	invalid := errors.New("identity: invalid JWK")
	switch j.Kty {
	case "OKP":
		x, err := base64.RawURLEncoding.DecodeString(j.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return verificationKey{}, "", invalid
		}
		return verificationKey{"EdDSA", ed25519.PublicKey(x)}, "", nil
	case "EC":
		x, ex := base64.RawURLEncoding.DecodeString(j.X)
		y, ey := base64.RawURLEncoding.DecodeString(j.Y)
		if ex != nil || ey != nil || len(x) != 32 || len(y) != 32 {
			return verificationKey{}, "", invalid
		}
		pk, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return verificationKey{}, "", invalid
		}
		return verificationKey{"ES256", pk}, "", nil
	default: // RSA, the only remaining supported type.
		n, en := base64.RawURLEncoding.DecodeString(j.N)
		e, ee := base64.RawURLEncoding.DecodeString(j.E)
		if en != nil || ee != nil || len(e) == 0 || len(e) > 4 {
			return verificationKey{}, "", invalid
		}
		exponent := new(big.Int).SetBytes(e).Int64()
		if exponent < 3 || exponent > 2147483647 || exponent%2 == 0 {
			return verificationKey{}, "", invalid
		}
		modulus := new(big.Int).SetBytes(n)
		if modulus.BitLen() < 2048 {
			return verificationKey{}, "", invalid
		}
		// A longer key is valid elsewhere (Kubernetes publishes any RSA size), but
		// this library bounds verification cost: skip it rather than fail the set.
		if modulus.BitLen() > 4096 {
			return verificationKey{}, skipSize, nil
		}
		return verificationKey{"RS256", &rsa.PublicKey{N: modulus, E: int(exponent)}}, "", nil
	}
}
