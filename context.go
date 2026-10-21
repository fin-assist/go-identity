package identity

import (
	"context"
	"errors"
	"strings"
)

// Model is the identity required for one method/caller pair.
type Model uint8

const (
	// User requires a verified access token; user_id comes only from its sub.
	User Model = iota + 1
	// System requires a verified caller; user_id must come from a system request.
	System
	// NoUser requires a verified caller but no user access token (auth/JWKS RPCs).
	NoUser
)

type identityKey struct{}
type principal struct {
	userID, caller, token string
	model                 Model
}

// UserID returns the verified access-token sub, never a system request field.
func UserID(ctx context.Context) (string, bool) {
	p, ok := ctx.Value(identityKey{}).(principal)
	return p.userID, ok && p.model == User && p.userID != ""
}

// Caller returns the verified service caller (absent for an HTTP edge request).
func Caller(ctx context.Context) (string, bool) {
	p, ok := ctx.Value(identityKey{}).(principal)
	return p.caller, ok && p.caller != ""
}

// SystemUserID accepts an explicit request user_id only after System admission.
// A user or unauthenticated invocation cannot impersonate a system request.
// An empty field or wrong model returns an internal error, without echoing input.
func SystemUserID(ctx context.Context, field string) (string, error) {
	p, ok := ctx.Value(identityKey{}).(principal)
	if !ok || p.model != System || strings.TrimSpace(field) == "" {
		return "", errors.New("identity: system user ID required")
	}
	return field, nil
}

func bearer(values []string) (string, bool) {
	if len(values) != 1 || len(values[0]) > maxToken+7 {
		return "", false
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	return token, ok && strings.EqualFold(scheme, "Bearer") && token != "" && !strings.ContainsAny(token, " \t\r\n")
}
