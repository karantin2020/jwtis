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
	app.Action = func() {
		var err error
		boltDB, err = openDB()
		defer func() {
			confRepo.save()
			internalsRepo.save()
			boltDB.Close()
		}()
		if err != nil {
			fmt.Printf("Couldn't open db: %s\n", err.Error())
			return
		}
		confRepo.setDB(boltDB)
		internalsRepo.setDB(boltDB)
		if err := internalsRepo.load(); err != nil {
			fmt.Println(err.Error())
			cli.Exit(1)
		}
		// checkDBPassword()
		fmt.Println("dbExists: ", dbExists)
		fmt.Println("dbCheckFault: ", dbCheckFault)
		fmt.Printf("internalsRepo.password: '%s'\n", string(internalsRepo.password))
		if dbExists {
			if err := confRepo.load(); err != nil {
				fmt.Println(err.Error())
				cli.Exit(1)
			}
		}
		printOptions()
	}
	app.Run(os.Args)
}
