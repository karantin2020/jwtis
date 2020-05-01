package gen_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	errors "github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	jose "gopkg.in/square/go-jose.v2"

	kitJWT "github.com/go-kit/kit/auth/jwt"
	kitGRPC "github.com/go-kit/kit/transport/grpc"
	"github.com/karantin2020/jwtis/pkg/repos/keys"
	. "github.com/karantin2020/jwtis/pkg/svc/gen"
	pb "github.com/karantin2020/jwtis/pkg/svc/pb"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"

	zerolog "github.com/philip-bui/grpc-zerolog"
	// _ "github.com/cockroachdb/errors/extgrpc"

	"github.com/abronan/valkeyrie/store"
	fuzz "github.com/google/gofuzz"
	"github.com/karantin2020/svalkey"
	"github.com/karantin2020/svalkey/testutils"
)

var (
	ErrUnexpectedExplosion = errors.Wrap(ErrInternal, "unexpected error explosion with panic")
	serverOptions          = []grpc.ServerOption{
		grpc_middleware.WithUnaryServerChain(
		// zerolog.NewUnaryServerInterceptor(),
		// UnaryServerErrorInterceptor(),
		),
		grpc_middleware.WithStreamServerChain(
		// StreamServerInterceptor(),
		),
	}
	testKID = "test_kid"
)

type GRPCMockedRepository struct{}

func (r *GRPCMockedRepository) NewJWT(ctx context.Context, req *NewJWTRequest) (*NewJWTResponse, error) {
	// TODO : implement me
	return nil, ErrUnimplemented
}

func (r *GRPCMockedRepository) RenewJWT(ctx context.Context, req *RenewJWTRequest) (*RenewJWTResponse, error) {
	// TODO : implement me
	return nil, ErrUnimplemented
}

func (r *GRPCMockedRepository) RevokeJWT(ctx context.Context, req *RevokeJWTRequest) (*RevokeJWTResponse, error) {
	// TODO : implement me
	return nil, ErrUnimplemented
}

func (r *GRPCMockedRepository) Auth(ctx context.Context, req *AuthRequest) (*AuthResponse, error) {
	panic(ErrUnexpectedExplosion)
	return nil, ErrUnimplemented
}

func (r *GRPCMockedRepository) Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	// TODO : implement me
	return &RegisterResponse{
		KID:     req.KID,
		AuthJWT: "",
		Keys: &keys.SigEncKeys{
			Sig: jose.JSONWebKey{
				Key: []byte("asddsaasddsaasddsaasddsaasddsaas"),
			},
			Enc: jose.JSONWebKey{},
		},
	}, nil
}

func (r *GRPCMockedRepository) UpdateKeys(ctx context.Context, req *UpdateKeysRequest) (*UpdateKeysResponse, error) {
	// TODO : implement me
	return nil, ErrUnimplemented
}

func (r *GRPCMockedRepository) ListKeys(ctx context.Context, req *ListKeysRequest) (*ListKeysResponse, error) {
	// TODO : implement me
	return nil, ErrUnimplemented
}

func (r *GRPCMockedRepository) DelKeys(ctx context.Context, req *DelKeysRequest) (*DelKeysResponse, error) {
	// TODO : implement me
	return nil, ErrUnimplemented
}

func (r *GRPCMockedRepository) PublicKeys(ctx context.Context, req *PublicKeysRequest) (*PublicKeysResponse, error) {
	// TODO : implement me
	return nil, ErrUnimplemented
}

func (r *GRPCMockedRepository) Ping(ctx context.Context, req *PingRequest) (*PingResponse, error) {
	// TODO : implement me
	return nil, ErrUnimplemented
}

func (r *GRPCMockedRepository) Ready(ctx context.Context, req *ReadyRequest) (*ReadyResponse, error) {
	// TODO : implement me
	return nil, ErrUnimplemented
}

const (
	grpcHostAndPort = "localhost:8082"
)

func generateJWTMeta() string {
	// TODO : customize
	return ""
}

func newTestStore(s store.Store) *svalkey.Store {
	testSecret := [32]byte{}
	fs := fuzz.New().NumElements(32, 32)
	fs.Fuzz(&testSecret)
	store, err := svalkey.NewJSONStore(s, []byte{1, 0}, testSecret)
	if err != nil {
		panic("NewKeysRepo() error: error create new store: " + err.Error())
	}
	return store
}

func newMockStore() store.Store {
	m := testutils.NewMock()
	return m
}

func newTestKeysRepo(t *testing.T) *keys.Repository {
	opts := &keys.RepoOptions{
		Store:  newTestStore(newMockStore()),
		Prefix: "test",
		Opts: &keys.DefaultOptions{
			SigAlg:          "ES256",
			SigBits:         256,
			EncAlg:          "ECDH-ES+A256KW",
			EncBits:         256,
			Expiry:          time.Hour * 4320,
			AuthTTL:         time.Hour * 72,
			RefreshTTL:      time.Hour * 720,
			RefreshStrategy: "noRefresh",
		},
	}
	keysRepo, err := keys.NewKeysRepo(opts)
	if err != nil {
		t.Fatalf("error create new keys repo: %s", err)
	}
	return keysRepo
}

func prepareTestServerClient(t *testing.T) ClientService {
	logger := log.NewLogfmtLogger(os.Stdout)
	logger = log.With(logger, "caller", log.Caller(4))
	logger = level.NewFilter(logger, level.AllowDebug())

	kr := newTestKeysRepo(t)
	encs := jose.A128GCM
	grpcService := NewServerService(kr, encs, logger)
	//authMiddleware := MakeEnsureValidJWTMiddleware(logger)
	endpoints := MakeEndpoints(grpcService, []endpoint.Middleware{}) //authMiddleware
	grpcServer := grpc.NewServer(serverOptions...)

	serverConn, err := net.Listen("tcp", grpcHostAndPort)
	if err != nil {
		panic(fmt.Sprintf("unable to listen: %+v", err))
	}
	defer grpcServer.GracefulStop()

	options := []kitGRPC.ServerOption{
		kitGRPC.ServerBefore(kitJWT.GRPCToContext()),
		//kitGRPC.ServerBefore(MakeAddStreamUUID(logger)),
	}

	service, err := NewGRPCServer(endpoints, logger, options...)
	if err != nil {
		level.Error(logger).Log("error", err)
	}

	go func() {
		pb.RegisterJWTISServiceServer(grpcServer, service)
		_ = grpcServer.Serve(serverConn)
	}()

	conn, err := grpc.Dial(grpcHostAndPort, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("unable to Dial: %+v", err)
	}

	clientOptions := []kitGRPC.ClientOption{kitGRPC.ClientBefore(kitJWT.ContextToGRPC())}
	client := NewClient(conn, logger, clientOptions...)

	return client
}

func testServerClient(t *testing.T, tests []testType) {
	logger := log.NewLogfmtLogger(os.Stdout)
	logger = log.With(logger, "caller", log.Caller(4))
	logger = level.NewFilter(logger, level.AllowDebug())

	kr := newTestKeysRepo(t)
	encs := jose.A128GCM
	grpcService := NewServerService(kr, encs, logger)
	//authMiddleware := MakeEnsureValidJWTMiddleware(logger)
	endpoints := MakeEndpoints(grpcService, []endpoint.Middleware{}) //authMiddleware
	grpcServer := grpc.NewServer(serverOptions...)

	serverConn, err := net.Listen("tcp", grpcHostAndPort)
	if err != nil {
		panic(fmt.Sprintf("unable to listen: %+v", err))
	}
	defer grpcServer.GracefulStop()

	options := []kitGRPC.ServerOption{
		kitGRPC.ServerBefore(kitJWT.GRPCToContext()),
		//kitGRPC.ServerBefore(MakeAddStreamUUID(logger)),
	}

	service, err := NewGRPCServer(endpoints, logger, options...)
	if err != nil {
		level.Error(logger).Log("error", err)
	}

	go func() {
		pb.RegisterJWTISServiceServer(grpcServer, service)
		_ = grpcServer.Serve(serverConn)
	}()

	conn, err := grpc.Dial(grpcHostAndPort, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("unable to Dial: %+v", err)
	}

	clientOptions := []kitGRPC.ClientOption{kitGRPC.ClientBefore(kitJWT.ContextToGRPC())}
	cl := NewClient(conn, logger, clientOptions...)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.test(t, cl)
		})
	}
}

type testType struct {
	name string
	test func(t *testing.T, client ClientService)
}

func testServerClientRegistered(t *testing.T, tests []testType) {
	logger := log.NewLogfmtLogger(os.Stdout)
	logger = log.With(logger, "caller", log.Caller(4))
	logger = level.NewFilter(logger, level.AllowDebug())

	kr := newTestKeysRepo(t)
	encs := jose.A128GCM
	grpcService := NewServerService(kr, encs, logger)
	//authMiddleware := MakeEnsureValidJWTMiddleware(logger)
	endpoints := MakeEndpoints(grpcService, []endpoint.Middleware{}) //authMiddleware
	grpcServer := grpc.NewServer(serverOptions...)

	serverConn, err := net.Listen("tcp", grpcHostAndPort)
	if err != nil {
		panic(fmt.Sprintf("unable to listen: %+v", err))
	}
	defer grpcServer.GracefulStop()

	options := []kitGRPC.ServerOption{
		kitGRPC.ServerBefore(kitJWT.GRPCToContext()),
		//kitGRPC.ServerBefore(MakeAddStreamUUID(logger)),
	}

	service, err := NewGRPCServer(endpoints, logger, options...)
	if err != nil {
		level.Error(logger).Log("error", err)
	}

	go func() {
		pb.RegisterJWTISServiceServer(grpcServer, service)
		_ = grpcServer.Serve(serverConn)
	}()

	conn, err := grpc.Dial(grpcHostAndPort, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("unable to Dial: %+v", err)
	}

	clientOptions := []kitGRPC.ClientOption{kitGRPC.ClientBefore(kitJWT.ContextToGRPC())}
	cl := NewClient(conn, logger, clientOptions...)

	ctx := context.Background()
	_, err = cl.Register(ctx, &RegisterRequest{
		KID: testKID,
	})
	if err != nil {
		t.Fatalf("unable to test: %+v", err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.test(t, cl)
		})
	}
}

func TestServerClient(t *testing.T) {
	var (
		refreshToken string
		authJWT      string
		// id           string
	)
	testServerClient(t, []testType{
		{
			name: "test Register",
			test: func(t *testing.T, client ClientService) {
				ctx := context.Background()
				resp, err := client.Register(ctx, &RegisterRequest{
					KID: testKID,
				})
				if err != nil {
					t.Fatalf("unable to test: %+v", err)
				}
				// TODO : check response (write the actual test)
				t.Logf("resp : %#v", resp)
				authJWT = resp.AuthJWT
				_ = authJWT
				resp, err = client.Register(ctx, &RegisterRequest{
					KID: testKID + "1",
				})
				if err != nil {
					t.Fatalf("unable to test: %+v", err)
				}
			},
		},
		{
			name: "test UpdateKeys",
			test: func(t *testing.T, client ClientService) {
				ctx := context.Background()
				resp, err := client.UpdateKeys(ctx, &UpdateKeysRequest{
					KID: testKID,
				})
				if err != nil {
					t.Fatalf("unable to test: %+v", err)
				}
				// TODO : check response (write the actual test)
				t.Logf("resp : %#v", resp)
				authJWT = resp.AuthJWT
				_ = authJWT
			},
		},
		{
			name: "test PublicKeys",
			test: func(t *testing.T, client ClientService) {
				ctx := context.Background()
				resp, err := client.PublicKeys(ctx, &PublicKeysRequest{
					KID: testKID,
				})
				if err != nil {
					t.Fatalf("unable to test: %+v", err)
				}
				// TODO : check response (write the actual test)
				t.Logf("resp : %#v", resp)
			},
		},
		{
			name: "test FetchListKeys",
			test: func(t *testing.T, client ClientService) {
				ctx := context.Background()
				resp, err := client.FetchListKeys(ctx, &ListKeysRequest{})
				if err != nil {
					t.Fatalf("unable to test: %+v", err)
				}
				// TODO : check response (write the actual test)
				t.Logf("resp : %#v", resp)
				for i := range resp {
					t.Logf("resp %d: %s", i, resp[i].KID)
				}
			},
		},
		{
			name: "test DeleteKeys",
			test: func(t *testing.T, client ClientService) {
				ctx := context.Background()
				resp, err := client.DelKeys(ctx, &DelKeysRequest{
					KID: testKID + "1",
				})
				if err != nil {
					t.Fatalf("unable to test: %+v", err)
				}
				// TODO : check response (write the actual test)
				t.Logf("resp : %#v", resp)
			},
		},
		{
			name: "test FetchListKeys after delete",
			test: func(t *testing.T, client ClientService) {
				ctx := context.Background()
				resp, err := client.FetchListKeys(ctx, &ListKeysRequest{})
				if err != nil {
					t.Fatalf("unable to test: %+v", err)
				}
				// TODO : check response (write the actual test)
				t.Logf("resp : %#v", resp)
				for i := range resp {
					t.Logf("resp %d: %s", i, resp[i].KID)
				}
			},
		},
		{
			name: "test NewJWT",
			test: func(t *testing.T, client ClientService) {
				ctx := context.Background()
				resp, err := client.NewJWT(ctx, &NewJWTRequest{
					KID: "test_kid",
				})
				if err != nil {
					t.Fatalf("unable to test: %+v", err)
				}
				// TODO : check response (write the actual test)
				t.Logf("resp : %#v", resp)
				refreshToken = resp.RefreshToken
				// id = resp.ID
			},
		},
		{
			name: "test RenewJWT",
			test: func(t *testing.T, client ClientService) {
				ctx := context.Background()
				resp, err := client.RenewJWT(ctx, &RenewJWTRequest{
					KID:          "test_kid",
					RefreshToken: refreshToken,
				})
				if err != nil {
					t.Fatalf("unable to test: %+v", err)
				}
				// TODO : check response (write the actual test)
				t.Logf("resp : %#v", resp)
			},
		},
		// {
		// 	name: "test RevokeJWT",
		// 	test: func(t *testing.T, client ClientService) {
		// 		ctx := context.Background()
		// 		err := client.RevokeJWT(ctx, &RevokeJWTRequest{})
		// 		if err != nil {
		// 			t.Fatalf("unable to test: %+v", err)
		// 		}
		// 		// TODO : check response (write the actual test)
		// 		t.Logf("resp : %#v", resp)
		// 	},
		// },
		{
			name: "test Auth",
			test: func(t *testing.T, client ClientService) {
				ctx := context.Background()
				resp, err := client.Auth(ctx, &AuthRequest{
					KID: "test_kid",
				})
				if err != nil {
					t.Fatalf("unable to test: %+v", err)
				}
				// TODO : check response (write the actual test)
				t.Logf("resp : %#v", resp)
			},
		},
	})
}

// classic grpc call for NewJWT
func TestGRPCNewJWT(t *testing.T) {
	logger := log.NewLogfmtLogger(os.Stdout)
	logger = log.With(logger, "caller", log.Caller(4))
	logger = level.NewFilter(logger, level.AllowDebug())

	kr := newTestKeysRepo(t)
	encs := jose.A128GCM
	grpcService := NewServerService(kr, encs, logger)
	//authMiddleware := MakeEnsureValidJWTMiddleware(logger)
	endpoints := MakeEndpoints(grpcService, []endpoint.Middleware{}) //authMiddleware
	grpcServer := grpc.NewServer(serverOptions...)

	serverConn, err := net.Listen("tcp", grpcHostAndPort)
	if err != nil {
		panic(fmt.Sprintf("unable to listen: %+v", err))
	}
	defer grpcServer.GracefulStop()

	options := []kitGRPC.ServerOption{
		kitGRPC.ServerBefore(kitJWT.GRPCToContext()),
		//kitGRPC.ServerBefore(MakeAddStreamUUID(logger)),
	}

	service, err := NewGRPCServer(endpoints, logger, options...)
	if err != nil {
		level.Error(logger).Log("error", err)
	}

	go func() {
		pb.RegisterJWTISServiceServer(grpcServer, service)
		_ = grpcServer.Serve(serverConn)
	}()

	conn, err := grpc.Dial(grpcHostAndPort, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("unable to Dial: %+v", err)
	}

	clientOptions := []kitGRPC.ClientOption{kitGRPC.ClientBefore(kitJWT.ContextToGRPC())}
	client := NewClient(conn, logger, clientOptions...)

	ctx := context.Background()
	_, err = client.Register(ctx, &RegisterRequest{
		KID: string("test_kid"),
	})
	if err != nil {
		t.Fatalf("unable to test: %+v", err)
	}

	ctx = context.Background()
	resp, err := client.NewJWT(ctx, &NewJWTRequest{
		KID: "test_kid",
	})
	if err != nil {
		t.Fatalf("unable to test: %+v", err)
	}
	// TODO : check response (write the actual test)
	t.Logf("resp : %#v", resp)
}

// classic grpc call for RenewJWT
func TestGRPCRenewJWT(t *testing.T) {
	logger := log.NewLogfmtLogger(os.Stdout)
	logger = log.With(logger, "caller", log.Caller(4))
	logger = level.NewFilter(logger, level.AllowDebug())

	kr := newTestKeysRepo(t)
	encs := jose.A128GCM
	grpcService := NewServerService(kr, encs, logger)
	//authMiddleware := MakeEnsureValidJWTMiddleware(logger)
	endpoints := MakeEndpoints(grpcService, []endpoint.Middleware{}) //authMiddleware
	grpcServer := grpc.NewServer()

	serverConn, err := net.Listen("tcp", grpcHostAndPort)
	if err != nil {
		panic(fmt.Sprintf("unable to listen: %+v", err))
	}
	defer grpcServer.GracefulStop()

	options := []kitGRPC.ServerOption{
		kitGRPC.ServerBefore(kitJWT.GRPCToContext()),
		//kitGRPC.ServerBefore(MakeAddStreamUUID(logger)),
	}

	service, err := NewGRPCServer(endpoints, logger, options...)
	if err != nil {
		level.Error(logger).Log("error", err)
	}

	go func() {
		pb.RegisterJWTISServiceServer(grpcServer, service)
		_ = grpcServer.Serve(serverConn)
	}()

	conn, err := grpc.Dial(grpcHostAndPort, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("unable to Dial: %+v", err)
	}

	clientOptions := []kitGRPC.ClientOption{kitGRPC.ClientBefore(kitJWT.ContextToGRPC())}
	client := NewClient(conn, logger, clientOptions...)

	ctx := context.Background()
	// TODO : load the payloads
	resp, err := client.RenewJWT(ctx, &RenewJWTRequest{})
	if err != nil {
		t.Fatalf("unable to test: %+v", err)
	}
	// TODO : check response (write the actual test)
	t.Logf("resp : %v", resp)
}

// classic grpc call for RevokeJWT
func TestGRPCRevokeJWT(t *testing.T) {
	logger := log.NewLogfmtLogger(os.Stdout)
	logger = log.With(logger, "caller", log.Caller(4))
	logger = level.NewFilter(logger, level.AllowDebug())

	kr := newTestKeysRepo(t)
	encs := jose.A128GCM
	grpcService := NewServerService(kr, encs, logger)
	//authMiddleware := MakeEnsureValidJWTMiddleware(logger)
	endpoints := MakeEndpoints(grpcService, []endpoint.Middleware{}) //authMiddleware
	grpcServer := grpc.NewServer()

	serverConn, err := net.Listen("tcp", grpcHostAndPort)
	if err != nil {
		panic(fmt.Sprintf("unable to listen: %+v", err))
	}
	defer grpcServer.GracefulStop()

	options := []kitGRPC.ServerOption{
		kitGRPC.ServerBefore(kitJWT.GRPCToContext()),
		//kitGRPC.ServerBefore(MakeAddStreamUUID(logger)),
	}

	service, err := NewGRPCServer(endpoints, logger, options...)
	if err != nil {
		level.Error(logger).Log("error", err)
	}

	go func() {
		pb.RegisterJWTISServiceServer(grpcServer, service)
		_ = grpcServer.Serve(serverConn)
	}()

	conn, err := grpc.Dial(grpcHostAndPort, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("unable to Dial: %+v", err)
	}

	clientOptions := []kitGRPC.ClientOption{kitGRPC.ClientBefore(kitJWT.ContextToGRPC())}
	client := NewClient(conn, logger, clientOptions...)

	ctx := context.Background()
	// TODO : load the payloads
	resp, err := client.RevokeJWT(ctx, &RevokeJWTRequest{})
	if err != nil {
		t.Fatalf("unable to test: %+v", err)
	}
	// TODO : check response (write the actual test)
	t.Logf("resp : %v", resp)
}

// classic grpc call for Auth
func TestGRPCAuth(t *testing.T) {
	logger := log.NewLogfmtLogger(os.Stdout)
	logger = log.With(logger, "caller", log.Caller(4))
	logger = level.NewFilter(logger, level.AllowDebug())

	kr := newTestKeysRepo(t)
	encs := jose.A128GCM
	grpcService := NewServerService(kr, encs, logger)
	//authMiddleware := MakeEnsureValidJWTMiddleware(logger)
	endpoints := MakeEndpoints(grpcService, []endpoint.Middleware{}) //authMiddleware
	customFunc := func(p interface{}) (err error) {
		fmt.Println("is panic ErrUnexpectedExplosion:", Is(p.(error), ErrUnexpectedExplosion))
		// fmt.Printf("%+v\n", p.(error))
		if err, ok := p.(error); ok {
			return errors.Wrap(err, "panic handled")
		}
		return errors.Wrapf(ErrInternal, "non-error panic handled: %v", p)
	}
	// Shared options for the logger, with a custom gRPC code to log level function.
	opts := []grpc_recovery.Option{
		grpc_recovery.WithRecoveryHandler(customFunc),
	}
	grpcServer := grpc.NewServer(
		grpc_middleware.WithUnaryServerChain(
			zerolog.NewUnaryServerInterceptor(),
			UnaryServerErrorInterceptor(),
			grpc_recovery.UnaryServerInterceptor(opts...),
		),
		grpc_middleware.WithStreamServerChain(
			StreamServerInterceptor(),
			grpc_recovery.StreamServerInterceptor(opts...),
		),
	)

	serverConn, err := net.Listen("tcp", grpcHostAndPort)
	if err != nil {
		panic(fmt.Sprintf("unable to listen: %+v", err))
	}
	defer grpcServer.GracefulStop()

	options := []kitGRPC.ServerOption{
		kitGRPC.ServerBefore(kitJWT.GRPCToContext()),
		//kitGRPC.ServerBefore(MakeAddStreamUUID(logger)),
	}

	service, err := NewGRPCServer(endpoints, logger, options...)
	if err != nil {
		level.Error(logger).Log("error", err)
	}

	go func() {
		pb.RegisterJWTISServiceServer(grpcServer, service)
		_ = grpcServer.Serve(serverConn)
	}()

	conn, err := grpc.Dial(grpcHostAndPort, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("unable to Dial: %+v", err)
	}

	clientOptions := []kitGRPC.ClientOption{kitGRPC.ClientBefore(kitJWT.ContextToGRPC())}
	client := NewClient(conn, logger, clientOptions...)

	ctx := context.Background()
	// TODO : load the payloads
	resp, err := client.Auth(ctx, &AuthRequest{})
	if err != nil {
		t.Fatalf("unable to test: %+v", err)
	}
	// TODO : check response (write the actual test)
	t.Logf("resp : %v", resp)
}

// classic grpc call for Register
func TestGRPCRegister(t *testing.T) {
	// zzlog.Output(stzerolog.ConsoleWriter{Out: os.Stderr})
	logger := log.NewLogfmtLogger(os.Stdout)
	logger = log.With(logger, "caller", log.Caller(4))
	logger = level.NewFilter(logger, level.AllowDebug())

	kr := newTestKeysRepo(t)
	encs := jose.A128GCM
	grpcService := NewServerService(kr, encs, logger)
	//authMiddleware := MakeEnsureValidJWTMiddleware(logger)
	endpoints := MakeEndpoints(grpcService, []endpoint.Middleware{}) //authMiddleware
	// endpoints.WithLogging(logger)
	grpcServer := grpc.NewServer(
		serverOptions...,
	)

	serverConn, err := net.Listen("tcp", grpcHostAndPort)
	if err != nil {
		panic(fmt.Sprintf("unable to listen: %+v", err))
	}
	defer grpcServer.GracefulStop()

	options := []kitGRPC.ServerOption{
		// kitGRPC.ServerBefore(kitJWT.GRPCToContext()),
		//kitGRPC.ServerBefore(MakeAddStreamUUID(logger)),
	}

	service, err := NewGRPCServer(endpoints, logger, options...)
	if err != nil {
		level.Error(logger).Log("error", err)
	}

	go func() {
		pb.RegisterJWTISServiceServer(grpcServer, service)
		_ = grpcServer.Serve(serverConn)
	}()

	conn, err := grpc.Dial(grpcHostAndPort, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("unable to Dial: %+v", err)
	}

	clientOptions := []kitGRPC.ClientOption{kitGRPC.ClientBefore(kitJWT.ContextToGRPC())}
	client := NewClient(conn, logger, clientOptions...)

	ctx := context.Background()
	// TODO : load the payloads
	// fs := fuzz.New().NumElements(32, 32)
	kid := "test_kid"
	// fs.Fuzz(&kid)
	resp, err := client.Register(ctx, &RegisterRequest{
		KID: string(kid),
		// SigAlg          string
		// EncAlg          string
		// SigBits         int
		// EncBits         int
		// Expiry          time.Duration
		// AuthTTL         time.Duration
		// RefreshTTL      time.Duration
		// RefreshStrategy string
	})
	if err != nil {
		// st := status.Convert(err)
		t.Fatalf("register unable to test: %+v, code: %s", err, status.Code(err))
	}
	// TODO : check response (write the actual test)
	t.Logf("resp : %#v", resp)
	t.Logf("resp.Keys : %#v", resp.Keys)
	t.Logf("resp.Keys.Sig.Key : %#v", resp.Keys.Sig.Key)
}

// classic grpc call for UpdateKeys
func TestGRPCUpdateKeys(t *testing.T) {
	logger := log.NewLogfmtLogger(os.Stdout)
	logger = log.With(logger, "caller", log.Caller(4))
	logger = level.NewFilter(logger, level.AllowDebug())

	kr := newTestKeysRepo(t)
	encs := jose.A128GCM
	grpcService := NewServerService(kr, encs, logger)
	//authMiddleware := MakeEnsureValidJWTMiddleware(logger)
	endpoints := MakeEndpoints(grpcService, []endpoint.Middleware{}) //authMiddleware
	grpcServer := grpc.NewServer()

	serverConn, err := net.Listen("tcp", grpcHostAndPort)
	if err != nil {
		panic(fmt.Sprintf("unable to listen: %+v", err))
	}
	defer grpcServer.GracefulStop()

	options := []kitGRPC.ServerOption{
		kitGRPC.ServerBefore(kitJWT.GRPCToContext()),
		//kitGRPC.ServerBefore(MakeAddStreamUUID(logger)),
	}

	service, err := NewGRPCServer(endpoints, logger, options...)
	if err != nil {
		level.Error(logger).Log("error", err)
	}

	go func() {
		pb.RegisterJWTISServiceServer(grpcServer, service)
		_ = grpcServer.Serve(serverConn)
	}()

	conn, err := grpc.Dial(grpcHostAndPort, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("unable to Dial: %+v", err)
	}

	clientOptions := []kitGRPC.ClientOption{kitGRPC.ClientBefore(kitJWT.ContextToGRPC())}
	client := NewClient(conn, logger, clientOptions...)

	ctx := context.Background()
	// TODO : load the payloads
	resp, err := client.UpdateKeys(ctx, &UpdateKeysRequest{})
	if err != nil {
		t.Fatalf("unable to test: %+v", err)
	}
	// TODO : check response (write the actual test)
	t.Logf("resp : %v", resp)
}

// half duplex for ListKeys
func TestGRPCListKeys(t *testing.T) {
	logger := log.NewLogfmtLogger(os.Stdout)
	logger = log.With(logger, "caller", log.Caller(4))
	logger = level.NewFilter(logger, level.AllowDebug())

	kr := newTestKeysRepo(t)
	encs := jose.A128GCM
	grpcService := NewServerService(kr, encs, logger)
	//authMiddleware := MakeEnsureValidJWTMiddleware(logger)
	endpoints := MakeEndpoints(grpcService, []endpoint.Middleware{}) //authMiddleware
	grpcServer := grpc.NewServer()

	serverConn, err := net.Listen("tcp", grpcHostAndPort)
	if err != nil {
		panic(fmt.Sprintf("unable to listen: %+v", err))
	}
	defer grpcServer.GracefulStop()

	options := []kitGRPC.ServerOption{
		kitGRPC.ServerBefore(kitJWT.GRPCToContext()),
		//kitGRPC.ServerBefore(MakeAddStreamUUID(logger)),
	}

	service, err := NewGRPCServer(endpoints, logger, options...)
	if err != nil {
		level.Error(logger).Log("error", err)
	}

	go func() {
		pb.RegisterJWTISServiceServer(grpcServer, service)
		_ = grpcServer.Serve(serverConn)
	}()

	conn, err := grpc.Dial(grpcHostAndPort, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("unable to Dial: %+v", err)
	}

	clientOptions := []kitGRPC.ClientOption{kitGRPC.ClientBefore(kitJWT.ContextToGRPC())}
	client := NewClient(conn, logger, clientOptions...)

	ctx := context.Background()
	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)
	// simulate broadcasting messages
	go func() {
		// ticker := time.NewTicker(2 * time.Second)
		stopTimer := time.After(12 * time.Second)
		for {
			select {
			case <-ctx.Done():
				logger.Log("server", "stop")
				return
			// case <-ticker.C:
			// 	grpcService.BroadcastListKeys() <- ListKeysResponse{}
			// 	logger.Log("broadcasting", "ListKeys <- ListKeysResponse{}")
			case <-stopTimer:
				logger.Log("server", "end of life")
				// ticker.Stop()
				cancel()
			}
		}
	}()
	// client receive loop
	go func() {
		logger.Log("client", "waiting for messages")
		for {
			select {
			case <-ctx.Done():
				t.Log("Context done")
				return
			case message := <-client.ReceiveListKeys():
				// TODO : check response (write the actual test)

				t.Logf("kid : %v", message.KID)
				// t.Logf("expiry : %v", message.Keys.Expiry)
				// t.Logf("authTTL : %v", message.Keys.AuthTTL)
				// t.Logf("refreshTTL : %v", message.Keys.RefreshTTL)
				// t.Logf("refreshStrategy : %v", message.Keys.RefreshStrategy)
				// t.Logf("pubSigKey : %v", message.Keys.Sig)
				// t.Logf("pubEncKey : %v", message.Keys.Enc)
				// t.Logf("locked : %v", message.Keys.Locked)
				// t.Logf("valid : %v", message.Keys.Valid)
				// t.Logf("expired : %v", message.Keys.Expired)
			}
		}
	}()
	logger.Log("client", "placing call to ListKeys")
	_, err = client.Register(ctx, &RegisterRequest{
		KID: testKID,
	})
	if err != nil {
		t.Fatalf("unable to test: %+v", err)
	}
	_, err = client.Register(ctx, &RegisterRequest{
		KID: testKID + "1",
	})
	if err != nil {
		t.Fatalf("unable to test: %+v", err)
	}
	// TODO : load the payloads
	err = client.CallListKeys(ctx, &ListKeysRequest{})
	if err != nil && err.Error() != "rpc error: code = Canceled desc = context canceled" {
		t.Fatalf("unable to test: %+v", err)
	}
	logger.Log("client", "end of test")
}

// classic grpc call for DelKeys
func TestGRPCDelKeys(t *testing.T) {
	logger := log.NewLogfmtLogger(os.Stdout)
	logger = log.With(logger, "caller", log.Caller(4))
	logger = level.NewFilter(logger, level.AllowDebug())

	kr := newTestKeysRepo(t)
	encs := jose.A128GCM
	grpcService := NewServerService(kr, encs, logger)
	//authMiddleware := MakeEnsureValidJWTMiddleware(logger)
	endpoints := MakeEndpoints(grpcService, []endpoint.Middleware{}) //authMiddleware
	grpcServer := grpc.NewServer()

	serverConn, err := net.Listen("tcp", grpcHostAndPort)
	if err != nil {
		panic(fmt.Sprintf("unable to listen: %+v", err))
	}
	defer grpcServer.GracefulStop()

	options := []kitGRPC.ServerOption{
		kitGRPC.ServerBefore(kitJWT.GRPCToContext()),
		//kitGRPC.ServerBefore(MakeAddStreamUUID(logger)),
	}

	service, err := NewGRPCServer(endpoints, logger, options...)
	if err != nil {
		level.Error(logger).Log("error", err)
	}

	go func() {
		pb.RegisterJWTISServiceServer(grpcServer, service)
		_ = grpcServer.Serve(serverConn)
	}()

	conn, err := grpc.Dial(grpcHostAndPort, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("unable to Dial: %+v", err)
	}

	clientOptions := []kitGRPC.ClientOption{kitGRPC.ClientBefore(kitJWT.ContextToGRPC())}
	client := NewClient(conn, logger, clientOptions...)

	ctx := context.Background()
	// TODO : load the payloads
	resp, err := client.DelKeys(ctx, &DelKeysRequest{})
	if err != nil {
		t.Fatalf("unable to test: %+v", err)
	}
	// TODO : check response (write the actual test)
	t.Logf("resp : %v", resp)
}

// classic grpc call for PublicKeys
func TestGRPCPublicKeys(t *testing.T) {
	logger := log.NewLogfmtLogger(os.Stdout)
	logger = log.With(logger, "caller", log.Caller(4))
	logger = level.NewFilter(logger, level.AllowDebug())

	kr := newTestKeysRepo(t)
	encs := jose.A128GCM
	grpcService := NewServerService(kr, encs, logger)
	//authMiddleware := MakeEnsureValidJWTMiddleware(logger)
	endpoints := MakeEndpoints(grpcService, []endpoint.Middleware{}) //authMiddleware
	grpcServer := grpc.NewServer()

	serverConn, err := net.Listen("tcp", grpcHostAndPort)
	if err != nil {
		panic(fmt.Sprintf("unable to listen: %+v", err))
	}
	defer grpcServer.GracefulStop()

	options := []kitGRPC.ServerOption{
		kitGRPC.ServerBefore(kitJWT.GRPCToContext()),
		//kitGRPC.ServerBefore(MakeAddStreamUUID(logger)),
	}

	service, err := NewGRPCServer(endpoints, logger, options...)
	if err != nil {
		level.Error(logger).Log("error", err)
	}

	go func() {
		pb.RegisterJWTISServiceServer(grpcServer, service)
		_ = grpcServer.Serve(serverConn)
	}()

	conn, err := grpc.Dial(grpcHostAndPort, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("unable to Dial: %+v", err)
	}

	clientOptions := []kitGRPC.ClientOption{kitGRPC.ClientBefore(kitJWT.ContextToGRPC())}
	client := NewClient(conn, logger, clientOptions...)

	ctx := context.Background()
	// TODO : load the payloads
	resp, err := client.PublicKeys(ctx, &PublicKeysRequest{})
	if err != nil {
		t.Fatalf("unable to test: %+v", err)
	}
	// TODO : check response (write the actual test)
	t.Logf("resp : %v", resp)
}

// classic grpc call for Ping
func TestGRPCPing(t *testing.T) {
	logger := log.NewLogfmtLogger(os.Stdout)
	logger = log.With(logger, "caller", log.Caller(4))
	logger = level.NewFilter(logger, level.AllowDebug())

	kr := newTestKeysRepo(t)
	encs := jose.A128GCM
	grpcService := NewServerService(kr, encs, logger)
	//authMiddleware := MakeEnsureValidJWTMiddleware(logger)
	endpoints := MakeEndpoints(grpcService, []endpoint.Middleware{}) //authMiddleware
	grpcServer := grpc.NewServer()

	serverConn, err := net.Listen("tcp", grpcHostAndPort)
	if err != nil {
		panic(fmt.Sprintf("unable to listen: %+v", err))
	}
	defer grpcServer.GracefulStop()

	options := []kitGRPC.ServerOption{
		kitGRPC.ServerBefore(kitJWT.GRPCToContext()),
		//kitGRPC.ServerBefore(MakeAddStreamUUID(logger)),
	}

	service, err := NewGRPCServer(endpoints, logger, options...)
	if err != nil {
		level.Error(logger).Log("error", err)
	}

	go func() {
		pb.RegisterJWTISServiceServer(grpcServer, service)
		_ = grpcServer.Serve(serverConn)
	}()

	conn, err := grpc.Dial(grpcHostAndPort, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("unable to Dial: %+v", err)
	}

	clientOptions := []kitGRPC.ClientOption{kitGRPC.ClientBefore(kitJWT.ContextToGRPC())}
	client := NewClient(conn, logger, clientOptions...)

	ctx := context.Background()
	// TODO : load the payloads
	resp, err := client.Ping(ctx, &PingRequest{})
	if err != nil {
		t.Fatalf("unable to test: %+v", err)
	}
	// TODO : check response (write the actual test)
	t.Logf("resp : %v", resp)
}

// classic grpc call for Ready
func TestGRPCReady(t *testing.T) {
	logger := log.NewLogfmtLogger(os.Stdout)
	logger = log.With(logger, "caller", log.Caller(4))
	logger = level.NewFilter(logger, level.AllowDebug())

	kr := newTestKeysRepo(t)
	encs := jose.A128GCM
	grpcService := NewServerService(kr, encs, logger)
	//authMiddleware := MakeEnsureValidJWTMiddleware(logger)
	endpoints := MakeEndpoints(grpcService, []endpoint.Middleware{}) //authMiddleware
	grpcServer := grpc.NewServer()

	serverConn, err := net.Listen("tcp", grpcHostAndPort)
	if err != nil {
		panic(fmt.Sprintf("unable to listen: %+v", err))
	}
	defer grpcServer.GracefulStop()

	options := []kitGRPC.ServerOption{
		kitGRPC.ServerBefore(kitJWT.GRPCToContext()),
		//kitGRPC.ServerBefore(MakeAddStreamUUID(logger)),
	}

	service, err := NewGRPCServer(endpoints, logger, options...)
	if err != nil {
		level.Error(logger).Log("error", err)
	}

	go func() {
		pb.RegisterJWTISServiceServer(grpcServer, service)
		_ = grpcServer.Serve(serverConn)
	}()

	conn, err := grpc.Dial(grpcHostAndPort, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("unable to Dial: %+v", err)
	}

	clientOptions := []kitGRPC.ClientOption{kitGRPC.ClientBefore(kitJWT.ContextToGRPC())}
	client := NewClient(conn, logger, clientOptions...)

	ctx := context.Background()
	// TODO : load the payloads
	resp, err := client.Ready(ctx, &ReadyRequest{})
	if err != nil {
		t.Fatalf("unable to test: %+v", err)
	}
	// TODO : check response (write the actual test)
	t.Logf("resp : %v", resp)
}
