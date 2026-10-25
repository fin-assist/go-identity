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
// The writer receives finerr.InvalidToken() for a rejected token (401
// INVALID_TOKEN), or a bare UNAVAILABLE, CANCELED or DEADLINE_EXCEEDED status
// when the token could not be judged; finerr.ToREST does not map those, so the
// writer answers 500 INTERNAL_ERROR and the client keeps its session.
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
		if err != nil {
			if unjudged := notJudged(err); unjudged != nil {
				m.respond(w, r, unjudged)
				return
			}
			m.respond(w, r, finerr.InvalidToken())
			return
		}
		if strings.TrimSpace(id) == "" {
			m.respond(w, r, finerr.InvalidToken())
			return
		}
		ctx := context.WithValue(r.Context(), identityKey{}, principal{userID: id, token: token, model: User})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
