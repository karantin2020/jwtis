package main

import (
	"fmt"
	"os"

	bolt "github.com/coreos/bbolt"
	cli "github.com/jawher/mow.cli"
	"github.com/rs/zerolog"
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
	boltDB     *bolt.DB
	keysBucket *bolt.Bucket
	buckets    = map[string][]byte{
		"internalBucketName": []byte("internalBucket"),
		"configBucketName":   []byte("configBucket"),
		"keysBucketName":     []byte("keysBucket"),
	}
	app           *cli.Cli
	confRepo      configRepository
	internalsRepo internalRepository
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
		var err error
		log.Info().Msg("open db")
		boltDB, err = openDB()
		if err != nil {
			log.Error().Err(err).Msg("couldn't open db; exit")
			cli.Exit(1)
		}
		confRepo.setDB(boltDB)
		internalsRepo.init(boltDB, &confRepo)
		// internalsRepo.printConfigs()
	}
	app.After = func() {
		log.Info().Msg("save config repository")
		confRepo.save()
		log.Info().Msg("save internals repository")
		internalsRepo.save()
		log.Info().Msg("close db")
		boltDB.Close()
	}
	app.Action = func() {
		fmt.Println("jwtis works well")
	}
	app.Run(os.Args)
}
