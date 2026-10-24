package identity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	userv1 "github.com/fin-assist/contracts/gen/go/finassist/user/v1"
	"google.golang.org/grpc"
)

type keysClient func(context.Context, *userv1.GetSigningKeysRequest, ...grpc.CallOption) (*userv1.GetSigningKeysResponse, error)

func (f keysClient) GetSigningKeys(c context.Context, r *userv1.GetSigningKeysRequest, o ...grpc.CallOption) (*userv1.GetSigningKeysResponse, error) {
	return f(c, r, o...)
}
func TestUnitUserKeys(t *testing.T) {
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
func TestIntegrationHTTPKeysTLS(t *testing.T) {
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
	p, e := NewHTTPKeys(server.Client(), server.URL+"/jwks", nil)
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
		if _, e = NewHTTPKeys(server.Client(), address, nil); e == nil {
			t.Fatal(address)
		}
	}
	if _, e = NewHTTPKeys(nil, server.URL, nil); e == nil {
		t.Fatal("nil client")
	}
}

func TestIntegrationHTTPKeysAuthenticatedAndRotating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api-token")
	if e := os.WriteFile(path, []byte("api-one"), 0600); e != nil {
		t.Fatal(e)
	}
	source, _ := NewProjectedSource(path)
	expected := "Bearer api-one"
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != expected {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("keys"))
	}))
	defer server.Close()
	anonymous, _ := NewHTTPKeys(server.Client(), server.URL, nil)
	if _, e := anonymous.JWKS(context.Background()); e == nil {
		t.Fatal("anonymous keys fetch accepted")
	}
	auth, e := NewHTTPKeys(server.Client(), server.URL, source)
	if e != nil {
		t.Fatal(e)
	}
	if b, e := auth.JWKS(context.Background()); e != nil || string(b) != "keys" {
		t.Fatal(string(b), e)
	}
	replacement := path + ".new"
	if e = os.WriteFile(replacement, []byte("api-two"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(replacement, path); e != nil {
		t.Fatal(e)
	}
	expected = "Bearer api-two"
	if _, e = auth.JWKS(context.Background()); e != nil {
		t.Fatal("rotated API credential not used", e)
	}
	for _, bad := range []TokenSource{tokenFunc(func(context.Context) (string, error) { return "", errors.New("secret credential path") }), tokenFunc(func(context.Context) (string, error) { return "line\nbreak", nil })} {
		auth, _ = NewHTTPKeys(server.Client(), server.URL, bad)
		before := calls
		if _, e = auth.JWKS(context.Background()); e == nil || strings.Contains(e.Error(), "secret") {
			t.Fatal(e)
		}
		if calls != before {
			t.Fatal("request sent with invalid credential")
		}
	}
}
