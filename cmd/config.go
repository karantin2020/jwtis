package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"

	cli "github.com/jawher/mow.cli"
	"github.com/karantin2020/jwtis"
)

// http config
type httpConf struct {
	listen *string // ip:port to listen to
	tls    *bool   // Future feature
}

// Default keys generation options
type sign struct {
	sigAlg  *string // Default algorithn to be used for sign
	sigBits *int    // Default key size in bits for sign
}
type encryption struct {
	encAlg  *string // Default algorithn to be used for encrypt
	encBits *int    // Default key size in bits for encrypt
}
type keyGeneration struct {
	// keys generation options
	sign
	encryption
}
type setByUser struct {
	listenSetByUser   bool
	tlsSetByUser      bool
	sigAlgSetByUser   bool
	sigBitsSetByUser  bool
	encAlgSetByUser   bool
	encBitsSetByUser  bool
	selfNameSetByUser bool
	passwordSetByUser bool
	dbPathSetByUser   bool
}
type options struct {
	httpConf
	keyGeneration
	selfName *string // Name of this service

	// internal options
	password *string // Storage password. App generates password with db creation.
	// Later user must provide a password to access the database
	dbPath *string
	setByUser
}

var (
	conf options

	confListen   = []byte("jwtis.conf.listen")
	confTLS      = []byte("jwtis.conf.tls")
	confSigAlg   = []byte("jwtis.conf.sigAlg")
	confSigBits  = []byte("jwtis.conf.sigBits")
	confEncAlg   = []byte("jwtis.conf.encAlg")
	confEncBits  = []byte("jwtis.conf.encBits")
	confSelfName = []byte("jwtis.conf.selfName")
	confPassword = []byte("jwtis.conf.password")
	confDbPath   = []byte("jwtis.conf.dbPath")

	dbCheckKey   = []byte("jwtis.conf.dbCheckKey")
	dbCheckValue = []byte("jwtis.conf.dbCheckValue")
	dbExists     bool
	dbCheckFault bool
)

const (
	dbPathName = "keys.db" // default db folder name
)

func newConfigApp() *cli.Cli {
	app := cli.App(appName, appDescription)
	app.Version("v version", appVersion)
	app.Spec = "[OPTIONS]"
	conf = options{
		httpConf: httpConf{
			listen: app.String(cli.StringOpt{
				Name:      "l listen",
				Value:     "127.0.0.1:4343",
				Desc:      "ip:port to listen to",
				EnvVar:    envPrefix + "ADDRESS",
				SetByUser: &conf.listenSetByUser,
			}),
			tls: app.Bool(cli.BoolOpt{
				Name:      "tls",
				Value:     false,
				Desc:      "Use tls connection [not implemented yet]",
				EnvVar:    envPrefix + "TLS",
				SetByUser: &conf.tlsSetByUser,
			}),
		},
		keyGeneration: keyGeneration{
			// keys generation options
			sign: sign{
				sigAlg: app.String(cli.StringOpt{
					Name:      "sigAlg",
					Value:     "RS256",
					Desc:      "Default algorithn to be used for sign",
					EnvVar:    envPrefix + "SIG_ALG",
					SetByUser: &conf.sigAlgSetByUser,
				}),
				sigBits: app.Int(cli.IntOpt{
					Name:      "sigBits",
					Value:     2048,
					Desc:      "Default key size in bits for sign key",
					EnvVar:    envPrefix + "SIG_BITS",
					SetByUser: &conf.sigBitsSetByUser,
				}),
			},
			encryption: encryption{
				encAlg: app.String(cli.StringOpt{
					Name:      "encAlg",
					Value:     "RSA-OAEP-256",
					Desc:      "Default algorithn to be used for encrypt",
					EnvVar:    envPrefix + "ENC_ALG",
					SetByUser: &conf.encAlgSetByUser,
				}),
				encBits: app.Int(cli.IntOpt{
					Name:      "encBits",
					Value:     2048,
					Desc:      "Default key size in bits for encrypt",
					EnvVar:    envPrefix + "ENC_BITS",
					SetByUser: &conf.encBitsSetByUser,
				}),
			},
		},
		selfName: app.String(cli.StringOpt{
			Name:      "n name",
			Value:     "JWTIS",
			Desc:      "Name of this service",
			EnvVar:    envPrefix + "NAME",
			SetByUser: &conf.selfNameSetByUser,
		}),
		password: app.String(cli.StringOpt{
			Name:      "p pswd",
			Value:     "",
			Desc:      "Storage password. App generates password with db creation. Later user must provide a password to access the database",
			EnvVar:    envPrefix + "PSWD",
			SetByUser: &conf.passwordSetByUser,
		}),
		dbPath: app.String(cli.StringOpt{
			Name:      "d dbPath",
			Value:     "./data/" + dbPathName,
			Desc:      "Path to store keys db",
			EnvVar:    envPrefix + "DB_PATH",
			SetByUser: &conf.dbPathSetByUser,
		}),
	}
	if err := conf.validate(); err != nil {
		log.Printf("Invalid options:\n%s\n", err.Error())
		app.PrintLongHelp()
		cli.Exit(1)
	}
	checkDbPath()
	return app
}

func printOptions() {
	fmt.Printf("Options found:\n")
	fmt.Println("conf.listen: ", *conf.listen)
	fmt.Println("conf.tls: ", *conf.tls)
	fmt.Println("conf.sigAlg: ", *conf.sigAlg)
	fmt.Println("conf.sigBits: ", *conf.sigBits)
	fmt.Println("conf.encAlg: ", *conf.encAlg)
	fmt.Println("conf.encBits: ", *conf.encBits)
	fmt.Println("conf.selfName: ", *conf.selfName)
	fmt.Println("conf.password: ", *conf.password)
	fmt.Println("conf.dbPath: ", *conf.dbPath)
}

func (o options) validate() error {
	return nil
}

func (o *options) store() error {
	bkt := buckets["internalBucketName"]
	ShouldSet(bkt, confListen, []byte(*conf.listen))
	ShouldSet(bkt, confTLS, strconv.AppendBool([]byte{}, *conf.tls))
	ShouldSet(bkt, confSigAlg, []byte(*conf.sigAlg))
	ShouldSet(bkt, confSigBits, strconv.AppendInt([]byte{}, int64(*conf.sigBits), 10))
	ShouldSet(bkt, confEncAlg, []byte(*conf.encAlg))
	ShouldSet(bkt, confEncBits, strconv.AppendInt([]byte{}, int64(*conf.encBits), 10))
	ShouldSet(bkt, confSelfName, []byte(*conf.selfName))
	ShouldSet(bkt, confPassword, []byte(*conf.password))
	ShouldSet(bkt, confDbPath, []byte(*conf.dbPath))

	ShouldSet(bkt, dbCheckKey, dbCheckValue)
	return nil
}

func (o *options) load() error {
	bkt := buckets["internalBucketName"]
	if dbExists && !conf.listenSetByUser {
		*conf.listen = string(ShouldGet(bkt, confListen)) //, []byte(*conf.listen))
	}
	var err error
	if dbExists && !conf.tlsSetByUser {
		tls := ShouldGet(bkt, confTLS)
		if *conf.tls, err = strconv.ParseBool(string(tls)); err != nil {
			return err
		}
	}
	if dbExists && !conf.sigAlgSetByUser {
		*conf.sigAlg = string(ShouldGet(bkt, confSigAlg)) //, []byte(*conf.sigAlg))
	}
	if dbExists && !conf.sigBitsSetByUser {
		sbits := ShouldGet(bkt, confSigBits)
		if *conf.sigBits, err = strconv.Atoi(string(sbits)); err != nil {
			return nil
		}
	}
	if dbExists && !conf.encAlgSetByUser {
		*conf.encAlg = string(ShouldGet(bkt, confEncAlg)) //, []byte(*conf.encAlg))
	}
	if dbExists && !conf.encBitsSetByUser {
		ebits := ShouldGet(bkt, confEncBits)
		if *conf.encBits, err = strconv.Atoi(string(ebits)); err != nil {
			return nil
		}
	}
	if dbExists && !conf.selfNameSetByUser {
		*conf.selfName = string(ShouldGet(bkt, confSelfName)) //, []byte(*conf.selfName))
	}
	if dbExists && !conf.passwordSetByUser {
		*conf.password = string(ShouldGet(bkt, confPassword)) //, []byte(*conf.password))
	}
	if dbExists && !conf.dbPathSetByUser {
		*conf.dbPath = string(ShouldGet(bkt, confDbPath)) //, []byte(*conf.dbPath))
	}
	return nil
}

func checkDbPath() {
	dir, _ := filepath.Split(*conf.dbPath)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		FatalF("Couldn't make db dir. Reason: %s\n", err.Error())
	}
}

// password: getPassword(passwordLength), // Storage password generated by this app
func getPassword(length int) string {
	numtries := 5
	var (
		err    error
		secret []byte
	)
	for secret, err = jwtis.GenerateSecret(length); err != nil; numtries-- {
		if numtries == 0 {
			FatalF("Couldn't generate secret key because of internal problem\n")
		}
	}
	return string(secret)
}

// FatalF prints message to log and then interrupts app execution
func FatalF(format string, v ...interface{}) {
	log.Printf(format, v...)
	cli.Exit(1)
}
