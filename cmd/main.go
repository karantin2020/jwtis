package main

import (
	"fmt"
	"os"

	bolt "github.com/coreos/bbolt"
	cli "github.com/jawher/mow.cli"
	"github.com/karantin2020/jwtis/http"
	"github.com/rs/zerolog"

	"github.com/karantin2020/jwtis"
)

const (
	appName        = "jwtis"
	appVersion     = "v0.0.1"
	appDescription = "JWT issuer server. Provides trusted JWT tokens\n" +
		"\nSource https://github.com/karantin2020/jwtis"
	envPrefix      = "JWTIS_"
	passwordLength = 32
)

var (
	boltDB  *bolt.DB
	buckets = map[string][]byte{
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
	app = newConfigApp()
	app.Before = func() {
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
		if *confRepo.verbose {
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
		}
		log = logger("")
		log.Info().Msgf("started %s %s", appName, appVersion)
		var err error
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
			cli.Exit(1)
		}
		greetingMsg()
		internalsRepo.printConfigs()
	}
	app.After = func() {
		log.Info().Msg("save internals repository")
		internalsRepo.save()
		log.Info().Msg("close db")
		boltDB.Close()
		log.Info().Msgf("finished %s %s", appName, appVersion)
	}
	app.Action = func() {
		fmt.Println("jwtis works well")
		srv := http.SetupServer(internalsRepo.Listen, "release")
		err := http.StartServer(srv)
		if err != nil {
			fmt.Println("server error:", err.Error())
		}
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
