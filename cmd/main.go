package main

import (
	"fmt"
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
	boltDB         *bolt.DB
	keysBucket     *bolt.Bucket
	keysBucketName = []byte("keysBucket")
	app            *cli.Cli
	password       string
)

func main() {
	app = newConfigApp()
	app.Action = func() {
		var err error
		boltDB, err = openDB()
		defer boltDB.Close()
		if err != nil {
			fmt.Printf("Couldn't open db: %s\n", err.Error())
			return
		}
		checkDBPassword()
		if !dbExists {
			conf.store()
		}
	}
	app.Run(os.Args)
}
