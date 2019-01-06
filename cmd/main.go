package main

import (
	"os"

	"github.com/dgraph-io/badger"
)

const (
	appName        = "jwtis"
	appVersion     = "v0.0.1"
	appDescription = "JWT issuer server. Provides trusted JWT tokens"
	envPrefix      = "JWTIS_"
	passwordLength = 32
)

var (
	db *badger.DB
)

func main() {
	app := newConfigApp()
	db = openDB()
	defer db.Close()
	app.Run(os.Args)
}
