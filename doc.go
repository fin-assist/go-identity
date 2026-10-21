// Package identity verifies user and service identities for FinAssist Go services.
//
// Services inject clocks, issuer/audience settings, key providers and an optional
// Observer; this package reads no environment and starts no background goroutines.
// UserVerifier checks access JWTs against cached user JWKS. KubernetesVerifier
// checks projected ServiceAccount tokens; StageVerifier binds each stage key to
// one caller and is unavailable in prod. Server enforces an exact caller/model
// table for unary and streaming RPCs. HTTP authenticates protected bank-bff routes;
// UnaryClient and StreamClient forward only verified user credentials and the
// current service token. KeyCache.Run is an explicit service-owned lifecycle job.
//
// Identity does not replace object ownership checks or the service's tombstone
// interceptor. See README.md for bootstrap, rotation, wiring and method checklists.
package identity
