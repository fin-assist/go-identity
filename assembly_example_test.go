package identity_test

import (
	"context"
	"time"

	"github.com/fin-assist/go-grpc/client"
	"github.com/fin-assist/go-grpc/server"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"

	"github.com/fin-assist/go-identity"
)

func ExampleNewAssembly() {
	// cfg holds the service's own configuration: ENV and the AUTH_* variables.
	cfg := struct{ Env, UserPeer string }{Env: "prod", UserPeer: "dns:///user.finassist.svc.cluster.local:9090"}
	registry := prometheus.NewRegistry() // the service registry

	id, err := identity.NewAssembly(identity.AssemblyOptions{
		Env:        cfg.Env, // "prod" or "stage"; AUTH_MODE=insecure-dev stays service code
		Service:    "analytics",
		UserIssuer: "configured-user-issuer", UserAudience: "configured-user-audience",
		DialUser: func(tokens identity.TokenSource) (*grpc.ClientConn, error) {
			return client.Dial(cfg.UserPeer, client.Options{
				Peer: "user", Tokens: tokens,
				Retry: []string{"finassist.user.v1.UserInternalService/GetSigningKeys"},
			})
		},
		Kubernetes: identity.KubernetesOptions{TokenFile: "/var/run/secrets/finassist/token"},
		Stage:      identity.StageKeyFiles{ /* only with Env "stage" */ },
		Clock:      time.Now, Registerer: registry,
	})
	if err != nil {
		return // fail startup; never fall back to a weaker mode
	}
	defer func() { _ = id.Close() }()

	// The assembly is the verifier pair of go-grpc server and the token source of client.Dial.
	deps := server.Deps{Services: id, Users: id /* Logger, Metrics, Policy, Tombstones */}
	var outgoing client.TokenSource = id
	_, _ = deps, outgoing

	// Background key refresh is a service job (go-worker Job{Run: id.Run}).
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	go func() { _ = id.Run(ctx) }()
}
