package main

import (
	"fmt"
	"log"
	"os"

	bolt "github.com/coreos/bbolt"
	cli "github.com/jawher/mow.cli"
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
	password      string
)

func main() {
	app = newConfigApp()
	app.Before = func() {
		var err error
		boltDB, err = openDB()
		if err != nil {
			log.Printf("Couldn't open db: %s\n", err.Error())
			return
		}
		confRepo.setDB(boltDB)
		internalsRepo.init(boltDB, &confRepo)
		internalsRepo.printConfigs()
	}
	app.After = func() {
		log.Println("save config repository")
		confRepo.save()
		log.Println("save internals repository")
		internalsRepo.save()
		log.Println("close db")
		boltDB.Close()
	}
	app.Action = func() {
		fmt.Println("jwtis works well")
	}
	app.Run(os.Args)
}
