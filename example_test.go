package identity_test

import (
	"context"
	"net/http"
	"time"

	analyticsv1 "github.com/fin-assist/contracts/gen/go/finassist/analytics/v1"
	userv1 "github.com/fin-assist/contracts/gen/go/finassist/user/v1"
	"google.golang.org/grpc"

	"github.com/fin-assist/go-identity"
)

func ExampleNewUserVerifier() {
	// The service owns the connection, issuer, audience and clock settings.
	var conn *grpc.ClientConn
	keys, err := identity.NewKeyCache(identity.UserKeys{Client: userv1.NewUserInternalServiceClient(conn)}, time.Now, 10*time.Minute)
	if err != nil {
		return
	}
	verifier, err := identity.NewUserVerifier(keys, identity.VerifyOptions{Issuer: "configured-user-issuer", Audience: "configured-user-audience", Clock: time.Now})
	if err != nil {
		return
	}
	_ = verifier // Pass to the server and HTTP middleware; run keys.Run in a service job.
}

func ExampleNewServer() {
	var services identity.ServiceChecker
	var users identity.UserChecker
	table := identity.AccessTable{
		"/finassist.analytics.v1.AnalyticsService/GetAnalytics": {"bank-bff": identity.User, "assistant": identity.System},
	}
	auth, err := identity.NewServer(table, services, users, nil)
	if err != nil {
		return
	}
	server := grpc.NewServer(grpc.ChainUnaryInterceptor(auth.Unary()), grpc.ChainStreamInterceptor(auth.Stream()))
	_ = server
}

func ExampleNewProjectedSource() {
	source, err := identity.NewProjectedSource("/var/run/secrets/finassist/token")
	if err != nil {
		return
	}
	unary := identity.UnaryClient(source)
	stream := identity.StreamClient(source)
	_, _ = unary, stream // Install both on every service-owned gRPC connection.
}

func ExampleNewStageSource() {
	source, err := identity.NewStageSource("stage", identity.StageOptions{KeyFile: "/etc/finassist/bank-bff.pem", Caller: "bank-bff", Issuer: "configured-stage-issuer", Clock: time.Now})
	if err != nil {
		return
	}
	_ = source // Constructor refuses env=prod; select the mode explicitly in service config.
}

func ExampleNewHTTP() {
	var verifier identity.UserChecker
	// Use the service's OpenAPI-compatible error writer in real wiring.
	writeError := func(w http.ResponseWriter, r *http.Request, err error) {}
	auth, err := identity.NewHTTP(verifier, writeError)
	if err != nil {
		return
	}
	protected := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, _ := identity.UserID(r.Context())
		_ = userID // Calls using r.Context() forward the original verified access token.
	}))
	_ = protected
}

func ExampleSystemUserID() {
	handler := func(ctx context.Context, request *analyticsv1.GetAnalyticsRequest) (string, error) {
		return identity.SystemUserID(ctx, request.GetUserId())
	}
	_ = handler // Register in a System method, check its error before accessing data.
}

func ExampleNewObservedKeyCache() {
	// The service owns the HTTP client (cluster CA), the registry and the job lifecycle.
	var client *http.Client
	provider, err := identity.NewHTTPKeys(client, "https://kubernetes.default.svc/openid/v1/jwks", nil)
	if err != nil {
		return
	}
	var metrics *identity.Metrics // identity.NewMetrics(serviceRegistry), shared with verifiers.
	keys, err := identity.NewObservedKeyCache(provider, time.Now, time.Hour, "service", metrics)
	if err != nil {
		return
	}
	_ = keys // Pass to NewKubernetesVerifier; unsupported JWKs show up in finassist_identity_jwks_skipped_keys.
}
