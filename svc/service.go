package svc

import (
	"net"
	"os"
	"os/signal"
	"syscall"

	kitJWT "github.com/go-kit/kit/auth/jwt"
	endpoint "github.com/go-kit/kit/endpoint"
	log "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	kitGRPC "github.com/go-kit/kit/transport/grpc"
	"github.com/karantin2020/jwtis"
	"github.com/pkg/errors"

	pb "github.com/karantin2020/jwtis/svc/pb"
	group "github.com/oklog/run"

	grpc "google.golang.org/grpc"
	jose "gopkg.in/square/go-jose.v2"

	"github.com/karantin2020/jwtis/svc/gen"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
)

// ServerOpts struct holds all server options
type ServerOpts struct {
	MetricsAddr     string
	Addr            string
	KeysRepo        *jwtis.KeysRepository
	ContEnc         jose.ContentEncryption
	Logger          log.Logger
	G               *group.Group
	CancelInterrupt chan struct{}
}

// Run starts server process
func Run(opts ServerOpts) {
	logger := log.With(opts.Logger, "component", "grpc_server")
	grpcService := gen.NewServerService(opts.KeysRepo, opts.ContEnc, logger)
	//authMiddleware := MakeEnsureValidJWTMiddleware(logger)
	endpoints := gen.MakeEndpoints(grpcService, []endpoint.Middleware{}) //authMiddleware

	initGRPCHandler(opts.Addr, endpoints, opts.CancelInterrupt, opts.Logger, opts.G)
	initCancelInterrupt(opts.Logger, opts.CancelInterrupt, opts.G)
	logger.Log("exit", opts.G.Run())
}

func initGRPCHandler(
	addr string,
	endpoints gen.Endpoints,
	cancelInterrupt chan struct{},
	logger log.Logger,
	g *group.Group,
) {
	// options := defaultGRPCOptions(logger)
	// Add your GRPC options here
	panicFunc := func(p interface{}) (err error) {
		level.Error(logger).Log("panic", p, "status", "exit")
		close(cancelInterrupt)
		return nil
	}
	// Shared options for the logger, with a custom gRPC code to log level function.
	opts := []grpc_recovery.Option{
		grpc_recovery.WithRecoveryHandler(panicFunc),
	}
	serverOptions := []grpc.ServerOption{
		grpc_middleware.WithUnaryServerChain(
			grpc_recovery.UnaryServerInterceptor(opts...),
		),
		grpc_middleware.WithStreamServerChain(
			grpc_recovery.StreamServerInterceptor(opts...),
		),
	}
	grpcServer := grpc.NewServer(serverOptions...)
	options := []kitGRPC.ServerOption{
		kitGRPC.ServerBefore(kitJWT.GRPCToContext()),
		//kitGRPC.ServerBefore(MakeAddStreamUUID(logger)),
	}

	service, err := gen.NewGRPCServer(endpoints, logger, options...)
	if err != nil {
		level.Error(logger).Log("error", err)
	}

	serverConn, err := net.Listen("tcp", addr)
	if err != nil {
		panicFunc("unable to listen: " + err.Error())
	}

	g.Add(func() error {
		logger.Log("transport", "gRPC", "status", "start", "addr", addr)
		pb.RegisterJWTISServiceServer(grpcServer, service)
		return grpcServer.Serve(serverConn)
	}, func(error) {
		grpcServer.GracefulStop()
		logger.Log("transport", "gRPC", "status", "shutdown")
	})

}

func initCancelInterrupt(logger log.Logger, cancelInterrupt chan struct{}, g *group.Group) {
	g.Add(func() error {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		select {
		case sig := <-c:
			err := errors.Errorf("received signal %s", sig)
			level.Error(logger).Log("error", err)
			return err
		case <-cancelInterrupt:
			return nil
		}
	}, func(error) {
		close(cancelInterrupt)
	})
}
