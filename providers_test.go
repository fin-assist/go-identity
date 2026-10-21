package identity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	userv1 "github.com/fin-assist/contracts/gen/go/finassist/user/v1"
	"google.golang.org/grpc"
)

type keysClient func(context.Context, *userv1.GetSigningKeysRequest, ...grpc.CallOption) (*userv1.GetSigningKeysResponse, error)

func (f keysClient) GetSigningKeys(c context.Context, r *userv1.GetSigningKeysRequest, o ...grpc.CallOption) (*userv1.GetSigningKeysResponse, error) {
	return f(c, r, o...)
}
func TestUserKeys(t *testing.T) {
	if _, e := (UserKeys{}).JWKS(context.Background()); e == nil {
		t.Fatal("nil client")
	}
	for _, tc := range []struct {
		r    *userv1.GetSigningKeysResponse
		e    error
		good bool
	}{{&userv1.GetSigningKeysResponse{JwksJson: "keys"}, nil, true}, {nil, nil, false}, {nil, errors.New("secret"), false}, {&userv1.GetSigningKeysResponse{JwksJson: strings.Repeat("x", maxJWKS+1)}, nil, false}} {
		p := UserKeys{keysClient(func(ctx context.Context, _ *userv1.GetSigningKeysRequest, _ ...grpc.CallOption) (*userv1.GetSigningKeysResponse, error) {
			if ctx == nil {
				t.Fatal("no context")
			}
			return tc.r, tc.e
		})}
		b, e := p.JWKS(context.Background())
		if tc.good {
			if e != nil || string(b) != "keys" {
				t.Fatal(string(b), e)
			}
		} else if e == nil || strings.Contains(e.Error(), "secret") {
			t.Fatal("bad error", e)
		}
	}
}
func TestHTTPKeysTLS(t *testing.T) {
	status := http.StatusOK
	body := "keys"
	redirected := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/other" {
			redirected = true
		}
		if status == 302 {
			w.Header().Set("Location", "/other")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	p, e := NewHTTPKeys(server.Client(), server.URL+"/jwks")
	if e != nil {
		t.Fatal(e)
	}
	b, e := p.JWKS(context.Background())
	if e != nil || string(b) != "keys" {
		t.Fatal(string(b), e)
	}
	status = 302
	if _, e = p.JWKS(context.Background()); e == nil || redirected {
		t.Fatal("redirect followed")
	}
	status = 500
	if _, e = p.JWKS(context.Background()); e == nil {
		t.Fatal("server error ignored")
	}
	status = 200
	body = strings.Repeat("x", maxJWKS+1)
	if _, e = p.JWKS(context.Background()); e == nil {
		t.Fatal("oversized keys accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = p.JWKS(ctx); e == nil {
		t.Fatal("cancel ignored")
	}
	for _, address := range []string{"http://example.com", "https://u:p@example.com", "https://example.com?secret=1", "https://example.com/#fragment", "://bad"} {
		if _, e = NewHTTPKeys(server.Client(), address); e == nil {
			t.Fatal(address)
		}
	}
	if _, e = NewHTTPKeys(nil, server.URL); e == nil {
		t.Fatal("nil client")
	}
}
