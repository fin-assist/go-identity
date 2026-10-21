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
	"sync"
	"time"
)

const maxJWKS = 1 << 20

// JWKSProvider fetches trusted keys. Implementations must honour cancellation and
// must not use a URL or key supplied by a token. Errors are never sent to callers.
type JWKSProvider interface {
	JWKS(context.Context) ([]byte, error)
}

type verificationKey struct {
	algorithm string
	public    crypto.PublicKey
}

// KeyCache caches an immutable JWKS snapshot. It is safe for concurrent use.
// Refreshes, including failed ones and unknown kids, are limited to once a minute.
// A snapshot older than its interval is not used after a failed refresh.
type KeyCache struct {
	provider           JWKSProvider
	clock              func() time.Time
	interval           time.Duration
	gate               chan struct{}
	mu                 sync.RWMutex
	keys               map[string]verificationKey
	updated, attempted time.Time
	hasAttempt         bool
}

// NewKeyCache requires a provider, an injected clock and a maximum snapshot age of at least
// two minutes (10 minutes for user keys, one hour for Kubernetes keys).
func NewKeyCache(provider JWKSProvider, clock func() time.Time, interval time.Duration) (*KeyCache, error) {
	if provider == nil || clock == nil || interval < 2*time.Minute {
		return nil, errors.New("identity: invalid key cache options")
	}
	return &KeyCache{provider: provider, clock: clock, interval: interval, gate: make(chan struct{}, 1)}, nil
}

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
	if err := c.refresh(ctx); err != nil {
		return verificationKey{}, err
	}
	if err := ctx.Err(); err != nil {
		return verificationKey{}, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	k, ok = c.keys[kid]
	if !ok || c.clock().Sub(c.updated) >= c.interval {
		return verificationKey{}, errors.New("identity: key unavailable")
	}
	return k, nil
}

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
		return errors.New("identity: key fetch failed")
	}
	keys, err := parseJWKS(data)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.keys, c.updated = keys, c.clock()
	c.mu.Unlock()
	return nil
}

// Run proactively refreshes a snapshot at half its maximum age, checking once a
// minute. Failed loads retry on the next minute while the old snapshot is still
// valid. The service owns this job; cancellation waits at most five seconds for
// an already started shared fetch. The return value is ctx.Err().
func (c *KeyCache) Run(ctx context.Context) error {
	ticker := time.NewTicker(time.Minute)
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

func parseJWKS(data []byte) (map[string]verificationKey, error) {
	invalid := errors.New("identity: invalid JWKS")
	if len(data) > maxJWKS {
		return nil, invalid
	}
	var set struct {
		Keys []struct {
			Kty, Kid, Alg, Use, Crv, X, Y, N, E string
			KeyOps                              []string `json:"key_ops"`
		}
	}
	if json.Unmarshal(data, &set) != nil || len(set.Keys) == 0 || len(set.Keys) > 64 {
		return nil, invalid
	}
	keys := make(map[string]verificationKey, len(set.Keys))
	for _, j := range set.Keys {
		if j.Kid == "" || len(j.Kid) > 256 || (j.Use != "" && j.Use != "sig") {
			return nil, invalid
		}
		if _, exists := keys[j.Kid]; exists {
			return nil, invalid
		}
		if len(j.KeyOps) > 0 {
			found := false
			for _, op := range j.KeyOps {
				if op == "verify" {
					found = true
				}
			}
			if !found {
				return nil, invalid
			}
		}
		x, ex := base64.RawURLEncoding.DecodeString(j.X)
		var key verificationKey
		switch {
		case j.Kty == "OKP" && j.Crv == "Ed25519" && (j.Alg == "" || j.Alg == "EdDSA"):
			if ex != nil || len(x) != ed25519.PublicKeySize {
				return nil, invalid
			}
			key = verificationKey{"EdDSA", ed25519.PublicKey(x)}
		case j.Kty == "EC" && j.Crv == "P-256" && (j.Alg == "" || j.Alg == "ES256"):
			y, ey := base64.RawURLEncoding.DecodeString(j.Y)
			if ex != nil || ey != nil || len(x) != 32 || len(y) != 32 {
				return nil, invalid
			}
			pk, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
			if err != nil {
				return nil, invalid
			}
			key = verificationKey{"ES256", pk}
		case j.Kty == "RSA" && (j.Alg == "" || j.Alg == "RS256"):
			n, en := base64.RawURLEncoding.DecodeString(j.N)
			e, ee := base64.RawURLEncoding.DecodeString(j.E)
			if en != nil || ee != nil || len(n) < 256 || len(n) > 512 || len(e) == 0 || len(e) > 4 {
				return nil, invalid
			}
			exponent := new(big.Int).SetBytes(e).Int64()
			if exponent < 3 || exponent > 2147483647 || exponent%2 == 0 {
				return nil, invalid
			}
			modulus := new(big.Int).SetBytes(n)
			if modulus.BitLen() < 2048 {
				return nil, invalid
			}
			key = verificationKey{"RS256", &rsa.PublicKey{N: modulus, E: int(exponent)}}
		default:
			return nil, invalid
		}
		keys[j.Kid] = key
	}
	return keys, nil
}
