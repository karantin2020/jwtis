package main

import (
	"os"

	"github.com/dgraph-io/badger"
	cli "github.com/jawher/mow.cli"
)

const (
	appName        = "jwtis"
	appVersion     = "v0.0.1"
	appDescription = "JWT issuer server. Provides trusted JWT tokens"
	envPrefix      = "JWTIS_"
	passwordLength = 32
)

var (
	db  *badger.DB
	app *cli.Cli
)

func main() {
	app = newConfigApp()
	db = openDB()
	defer db.Close()
	app.Run(os.Args)
}
