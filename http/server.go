package http

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/karantin2020/jwtis"
	"github.com/karantin2020/jwtis/services/keyservice"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
)

var (
	log zerolog.Logger
)

// StartServer starts http server
func StartServer(srv *http.Server) error {
	var g errgroup.Group
	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)
	g.Go(func() error {
		<-sigint

		// We received an interrupt signal, shut down.
		log.Info().Msgf("server shutdown")
		err := srv.Shutdown(context.Background())
		if err != nil {
			log.Error().Err(err).Msgf("error from closing listeners, or context timeout")
			return fmt.Errorf("HTTP server Shutdown: %+v", err)
		}
		fmt.Print("\r")
		return nil
	})

	g.Go(func() error {
		log.Info().Msgf("listening and serving HTTP on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Error().Err(err).Msg("error starting or closing listener")
			return fmt.Errorf("HTTP server ListenAndServe: %+v", err)
		}
		return nil
	})

	return g.Wait()
}

// SetupServer configures new http server
func SetupServer(listen, mode string, keysRepo *jwtis.KeysRepository, zlog *zerolog.Logger) (*http.Server, error) {
	log = zlog.With().Str("c", "http").Logger()
	keySrvc, err := keyservice.New(keysRepo, zlog)
	if err != nil {
		log.Error().Err(err).Msg("error creating key service")
		return nil, fmt.Errorf("error creating key service: %s", err.Error())
	}
	r := LoadRouter(mode, keySrvc)
	return &http.Server{
		Addr:              listen,
		Handler:           r,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 1 * time.Second,
		IdleTimeout:       60 * time.Second,
		WriteTimeout:      15 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}, nil
}
