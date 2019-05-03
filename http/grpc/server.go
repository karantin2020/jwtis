package grpc

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"

	"google.golang.org/grpc"

	"github.com/karantin2020/jwtis"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
	jose "gopkg.in/square/go-jose.v2"

	pb "github.com/karantin2020/jwtis/http/pb"
	"github.com/karantin2020/jwtis/services/jwtservice"
	"github.com/karantin2020/jwtis/services/keyservice"
)

var (
	log zerolog.Logger
)

// StartServer starts http server
func StartServer( /* ctx context.Context,  */ srv pb.JWTISServer, addr string) error {
	listen, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	// register service
	server := grpc.NewServer()
	pb.RegisterJWTISServer(server, srv)

	// graceful shutdown
	var g errgroup.Group
	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)
	g.Go(func() error {
		<-sigint
		// sig is a ^C, handle it
		log.Info().Msg("shutting down gRPC server...")

		server.GracefulStop()
		fmt.Print("\r")
		// <-ctx.Done()
		return nil
	})
	g.Go(func() error {
		log.Info().Msgf("starting gRPC server on %s", addr)
		if err := server.Serve(listen); err != http.ErrServerClosed {
			log.Error().Err(err).Msg("error starting or closing listener")
			return fmt.Errorf("HTTP server ListenAndServe: %+v", err)
		}
		return nil
	})

	// start gRPC server
	log.Info().Msg("starting gRPC server...")
	return g.Wait()
}

// SetupServer configures new http server
func SetupServer(keysRepo *jwtis.KeysRepository,
	zlog *zerolog.Logger, contEnc jose.ContentEncryption) (pb.JWTISServer, error) {
	log = zlog.With().Str("c", "grpc").Logger()
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
	srv := NewJWTISServer(keySrvc, jwtSrvc)
	return srv, nil
}
