package identity

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/fin-assist/contracts/gen/go/finerr"
)

// HTTP authenticates protected bank-bff routes. Public routes must be registered
// separately. It is concurrency safe if the checker and responder are.
type HTTP struct {
	users   UserChecker
	respond func(http.ResponseWriter, *http.Request, error)
}

// NewHTTP requires a verifier and the service's contract-aware error writer.
// The writer receives only finerr.InvalidToken(), for a 401 INVALID_TOKEN response.
func NewHTTP(users UserChecker, respond func(http.ResponseWriter, *http.Request, error)) (*HTTP, error) {
	if users == nil || respond == nil {
		return nil, errors.New("identity: HTTP verifier and responder required")
	}
	return &HTTP{users, respond}, nil
}

// Middleware verifies Authorization before the handler and stores sub and the
// original access token. UnaryClient/StreamClient forward it as authorization.
func (m *HTTP) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearer(r.Header.Values("Authorization"))
		if !ok {
			m.respond(w, r, finerr.InvalidToken())
			return
		}
		id, err := m.users.VerifyUser(r.Context(), token)
		if err != nil || strings.TrimSpace(id) == "" {
			m.respond(w, r, finerr.InvalidToken())
			return
		}
		ctx := context.WithValue(r.Context(), identityKey{}, principal{userID: id, token: token, model: User})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
