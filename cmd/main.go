package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	bolt "github.com/coreos/bbolt"
	cli "github.com/jawher/mow.cli"
	server "github.com/karantin2020/jwtis/api/server"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"github.com/karantin2020/jwtis"
)

const (
	appName        = "jwtis"
	appDescription = "JWT issuer server. Provides trusted JWT tokens\n" +
		"\nSource https://github.com/karantin2020/jwtis"
	envPrefix      = "JWTIS_"
	passwordLength = 32
)

var (
	appVersion = "v0.3.1"
	boltDB     *bolt.DB
	buckets    = map[string][]byte{
		"internalBucketName": []byte("internalBucket"),
		"keysBucketName":     []byte("keysBucket"),
	}
	app           *cli.Cli
	confRepo      configRepository
	internalsRepo internalRepository
	keysRepo      jwtis.KeysRepository
	log           zerolog.Logger
)

func main() {
	// app = cli.App(appName, appDescription)
	// app.Version("V version", appVersion)

	app = newConfigApp()
	app.Before = func() {
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
		if *confRepo.verbose {
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
		}
		var err error
		log = logger("")
		if err = confRepo.validate(); err != nil {
			log.Error().Err(err).Msg("error validating flags")
			app.PrintLongHelp()
			cli.Exit(1)
		}
		log.Info().Msgf("started %s %s", appName, appVersion)
		log.Info().Msg("open db")
		boltDB, err = openDB()
		if err != nil {
			log.Error().Err(err).Msg("error in start up, couldn't open db; exit")
			cli.Exit(1)
		}
		internalsRepo.init(boltDB, &confRepo)

		err = keysRepo.Init(boltDB, buckets["keysBucketName"],
			&jwtis.DefaultOptions{
				SigAlg:     internalsRepo.SigAlg,
				SigBits:    internalsRepo.SigBits,
				EncAlg:     internalsRepo.EncAlg,
				EncBits:    internalsRepo.EncBits,
				Expiry:     internalsRepo.Expiry,
				AuthTTL:    internalsRepo.AuthTTL,
				RefreshTTL: internalsRepo.RefreshTTL,
			}, &internalsRepo.encKey, internalsRepo.nonce)
		if err != nil {
			log.Error().Err(err).Msg("error in start up init keys repository; exit")
			log.Info().Msg("close db")
			boltDB.Close()
			cli.Exit(1)
		}
		greetingMsg()
		internalsRepo.printConfigs()
	}
	app.After = exit
	app.Action = func() {
		fmt.Println("jwtis works well")
		srv, err := server.NewJWTISServer(internalsRepo.Listen,
			internalsRepo.ListenGrpc, &keysRepo,
			&log, internalsRepo.ContEnc)
		if err != nil {
			FatalF("error in setup http server")
		}
		var g errgroup.Group
		g.Go(func() error {
			err = srv.Run()
			if err != nil && err != http.ErrServerClosed {
				log.Error().Err(err).Msg("run server error")
				return err
			}
			return nil
		})
		g.Go(func() error {
			// Wait for interrupt signal to gracefully shutdown the server with
			// a timeout of 5 seconds.
			quit := make(chan os.Signal, 1)
			// kill (no param) default send syscanll.SIGTERM
			// kill -2 is syscall.SIGINT
			// kill -9 is syscall. SIGKILL but can"t be catch, so don't need add it
			signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
			<-quit
			fmt.Print("\r")
			log.Info().Msg("shutdown server on signal")
			// TODO: add shutdown timeout app option
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()
			err := srv.Shutdown(ctx)
			if err != nil {
				log.Error().Err(err).Msg("server shutdown error")
			}
			log.Info().Msg("http server gracefully shutdown")
			return nil
		})
		g.Wait()
		fmt.Println("jwtis finished work")
	}
	app.Run(os.Args)
}

func greetingMsg() {
	fmt.Printf("Welcome. Started %s version %s\n", appName, appVersion)
	if !dbExists {
		fmt.Printf("Created new bbolt database to store app's data\n")
		fmt.Printf("Generated new password: '%s'\n", string(internalsRepo.password))
		fmt.Printf("Please save the password safely, it's not recoverable\n")
	} else {
		fmt.Printf("Found existing bbolt database storing app's data\n")
		fmt.Printf("Use user inserted password to bboltDB\n")
	}
}

func exit() {
	log.Info().Msg("save internals repository")
	internalsRepo.save()
	log.Info().Msg("close db")
	boltDB.Close()
	log.Info().Msgf("finished %s %s", appName, appVersion)
}
