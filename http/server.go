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
	// idleConnsClosed := make(chan struct{})
	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)
	g.Go(func() error {
		<-sigint

		// We received an interrupt signal, shut down.
		err := srv.Shutdown(context.Background())
		// close(idleConnsClosed)
		if err != nil {
			// Error from closing listeners, or context timeout:
			return fmt.Errorf("HTTP server Shutdown: %+v", err)
		}
		fmt.Print("\r")
		// fmt.Println("\rstop server shutdown")
		return nil
	})

	g.Go(func() error {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			// Error starting or closing listener:
			return fmt.Errorf("HTTP server ListenAndServe: %+v", err)
		}
		fmt.Print("\r")
		// fmt.Println("\rstop listen and serve")
		return nil
	})

	// <-idleConnsClosed
	return g.Wait()
}

// SetupServer configures new http server
func SetupServer(listen, mode string, keysRepo *jwtis.KeysRepository, zlog *zerolog.Logger) (*http.Server, error) {
	log = zlog.With().Str("c", "http").Logger()
	keySrvc, err := keyservice.New(keysRepo, zlog)
	if err != nil {
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
