package serverpb

import (
	// errpb "github.com/karantin2020/errorpb"
	// "google.golang.org/grpc/codes"

	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	chi "github.com/go-chi/chi"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/karantin2020/jwtis"
	pb "github.com/karantin2020/jwtis/api/pb"
	"github.com/karantin2020/jwtis/services/jwtservice"
	"github.com/karantin2020/jwtis/services/keyservice"
	"github.com/rs/zerolog"
	"github.com/utrack/clay/server"
	"github.com/utrack/clay/transport"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	jose "gopkg.in/square/go-jose.v2"
)

var (
	log zerolog.Logger
)

// JWTISServer struct holds JWT handlers
type JWTISServer struct {
	khg     *keyservice.KeyService
	jhg     *jwtservice.JWTService
	httpSrv *http.Server
	grpcSrv *grpc.Server
	claySrv *server.Server
}

// GetDescription is a simple alias to the ServiceDesc constructor.
// It makes it possible to register the service implementation @ the server.
func (j *JWTISServer) GetDescription() transport.ServiceDesc {
	return pb.NewJWTISServiceDesc(j)
}

// NewJWTISServer returns new pb.JWTISServer instance
func NewJWTISServer(listen string, keysRepo *jwtis.KeysRepository,
	zlog *zerolog.Logger, contEnc jose.ContentEncryption) (pb.JWTISServer, error) {
	log = zlog.With().Str("c", "server").Logger()
	keySrvc, err := keyservice.New(keysRepo, zlog)
	if err != nil {
		log.Error().Err(err).Msg("error creating key service")
		return nil, fmt.Errorf("error creating key service: %s", err.Error())
	}
	jwtSrvc, err := jwtservice.New(keysRepo, zlog, contEnc)
	if err != nil {
		log.Error().Err(err).Msg("error creating jwt service")
		return nil, fmt.Errorf("error creating key service: %s", err.Error())
	}
	j := &JWTISServer{khg: keySrvc, jhg: jwtSrvc}
	j.Prepare(listen)
	return j, nil
}

// Prepare preconfigures server
func (j *JWTISServer) Prepare(listen string) error {
	host, portstr, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("error prepare server: %s", err.Error())
	}
	port, err := strconv.Atoi(portstr)
	if err != nil {
		return fmt.Errorf("error prepare server: %s", err.Error())
	}
	hmux := chi.NewRouter()
	j.httpSrv = &http.Server{
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 1 * time.Second,
		IdleTimeout:       60 * time.Second,
		WriteTimeout:      15 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	mws := UnaryPanicHandler()
	mw := grpc_middleware.ChainUnaryServer(mws)
	j.grpcSrv = grpc.NewServer(grpc.UnaryInterceptor(mw))

	j.claySrv = server.NewServer(
		40345,
		server.WithHost(host),
		server.WithHTTPPort(port),
		server.WithHTTPMux(hmux),
		server.WithHTTPServer(j.httpSrv),
		server.WithGRPCServer(j.grpcSrv),
	)
	return nil
}

// Run runes the server
func (j *JWTISServer) Run() error {
	err := j.claySrv.Run(j)
	if err != nil && err != http.ErrServerClosed {
		log.Fatal().Err(err).Msg("server unexpectedly interrupted")
	}
	return err
}

// Shutdown gracefuly stops the server with context ctx
func (j *JWTISServer) Shutdown(ctx context.Context) error {
	fmt.Print("\r")
	log.Info().Msg("gracefuly shutdown server")
	var gg errgroup.Group

	gg.Go(func() error {
		err := j.httpSrv.Shutdown(ctx)
		if err != nil {
			log.Error().Err(err).Msg("http server shutdown with error")
		}
		log.Info().Msg("http server exiting")
		return nil
	})
	gg.Go(func() error {
		j.grpcSrv.GracefulStop()
		log.Info().Msg("grpc server exiting")
		return nil
	})
	return gg.Wait()
}
