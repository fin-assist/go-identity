package identity

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"

	userv1 "github.com/fin-assist/contracts/gen/go/finassist/user/v1"
	"google.golang.org/grpc"
)

// SigningKeysClient is the GetSigningKeys part of the generated user client.
// Its connection must have a service-token client interceptor (including bootstrap).
type SigningKeysClient interface {
	GetSigningKeys(context.Context, *userv1.GetSigningKeysRequest, ...grpc.CallOption) (*userv1.GetSigningKeysResponse, error)
}

// UserKeys fetches JWKS over the authenticated internal gRPC connection.
// The client must be concurrency safe, as generated clients are.
type UserKeys struct{ Client SigningKeysClient }

// JWKS fetches keys with ctx and bounds the returned JSON. The service configures
// a receive-message limit on the connection as well (at most 1 MiB plus protobuf).
func (p UserKeys) JWKS(ctx context.Context) ([]byte, error) {
	if p.Client == nil {
		return nil, errors.New("identity: signing keys client required")
	}
	r, err := p.Client.GetSigningKeys(ctx, &userv1.GetSigningKeysRequest{}, grpc.MaxCallRecvMsgSize(maxJWKS+1024))
	if err != nil || r == nil || len(r.GetJwksJson()) > maxJWKS {
		return nil, errors.New("identity: signing key fetch failed")
	}
	return []byte(r.GetJwksJson()), nil
}

// HTTPKeys fetches Kubernetes JWKS from a pinned HTTPS URL. It is concurrency safe
// if the supplied client's transport is. It never follows redirects.
type HTTPKeys struct {
	client http.Client
	url    string
}

// NewHTTPKeys copies a service-owned client, keeping its TLS trust configuration.
// The URL must be HTTPS without credentials, query or fragment. Never disable TLS
// verification; install the cluster CA in the client's transport instead.
func NewHTTPKeys(client *http.Client, address string) (*HTTPKeys, error) {
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || client == nil {
		return nil, errors.New("identity: pinned HTTPS JWKS URL and client required")
	}
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &HTTPKeys{c, address}, nil
}

// JWKS fetches a bounded successful response; errors contain no URL or body.
func (p *HTTPKeys) JWKS(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil, errors.New("identity: invalid JWKS request")
	}
	r, err := p.client.Do(req)
	if err != nil {
		return nil, errors.New("identity: JWKS transport failed")
	}
	defer func() { _ = r.Body.Close() }()
	if r.StatusCode != http.StatusOK {
		return nil, errors.New("identity: JWKS endpoint failed")
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, maxJWKS+1))
	if err != nil || len(b) > maxJWKS {
		return nil, errors.New("identity: invalid JWKS body")
	}
	return b, nil
}
