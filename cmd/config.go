package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	cli "github.com/jawher/mow.cli"
	"github.com/karantin2020/jwtis"
)

var (
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
	confRepo = initConfigRepository(nil)
	confRepo.setDefaults()
	internalsRepo = initInternalRepository(nil)
	confRepo.listen = app.String(cli.StringOpt{
		Name:      "l listen",
		Value:     confRepo.defListen,
		Desc:      "ip:port to listen to",
		EnvVar:    envPrefix + "ADDRESS",
		SetByUser: &confRepo.listenSetByUser,
	})
	confRepo.tls = app.Bool(cli.BoolOpt{
		Name:      "tls",
		Value:     confRepo.defTLS,
		Desc:      "Use tls connection [not implemented yet]",
		EnvVar:    envPrefix + "TLS",
		SetByUser: &confRepo.tlsSetByUser,
	})
	confRepo.sigAlg = app.String(cli.StringOpt{
		Name:      "sigAlg",
		Value:     confRepo.defSigAlg,
		Desc:      "Default algorithn to be used for sign",
		EnvVar:    envPrefix + "SIG_ALG",
		SetByUser: &confRepo.sigAlgSetByUser,
	})
	confRepo.sigBits = app.Int(cli.IntOpt{
		Name:      "sigBits",
		Value:     confRepo.defSigBits,
		Desc:      "Default key size in bits for sign key",
		EnvVar:    envPrefix + "SIG_BITS",
		SetByUser: &confRepo.sigBitsSetByUser,
	})
	confRepo.encAlg = app.String(cli.StringOpt{
		Name:      "encAlg",
		Value:     confRepo.defEncAlg,
		Desc:      "Default algorithn to be used for encrypt",
		EnvVar:    envPrefix + "ENC_ALG",
		SetByUser: &confRepo.encAlgSetByUser,
	})
	confRepo.encBits = app.Int(cli.IntOpt{
		Name:      "encBits",
		Value:     confRepo.defEncBits,
		Desc:      "Default key size in bits for encrypt",
		EnvVar:    envPrefix + "ENC_BITS",
		SetByUser: &confRepo.encBitsSetByUser,
	})
	confRepo.selfName = app.String(cli.StringOpt{
		Name:      "n name",
		Value:     confRepo.defSelfName,
		Desc:      "Name of this service",
		EnvVar:    envPrefix + "NAME",
		SetByUser: &confRepo.selfNameSetByUser,
	})
	confRepo.password = app.String(cli.StringOpt{
		Name:      "p pswd",
		Value:     confRepo.defPassword,
		Desc:      "Storage password. App generates password with db creation. Later user must provide a password to access the database",
		EnvVar:    envPrefix + "PSWD",
		SetByUser: &confRepo.passwordSetByUser,
	})
	confRepo.dbPath = app.String(cli.StringOpt{
		Name:      "d dbPath",
		Value:     confRepo.defDbPath,
		Desc:      "Path to store keys db",
		EnvVar:    envPrefix + "DB_PATH",
		SetByUser: &confRepo.dbPathSetByUser,
	})
	if err := confRepo.validate(); err != nil {
		log.Printf("Invalid options:\n%s\n", err.Error())
		app.PrintLongHelp()
		cli.Exit(1)
	}
	// printOptions()
	checkDbPath()
	return app
}

func printOptions() {
	fmt.Printf("Options found:\n")
	fmt.Println("conf.listen: ", *confRepo.listen)
	fmt.Println("conf.tls: ", *confRepo.tls)
	fmt.Println("conf.sigAlg: ", *confRepo.sigAlg)
	fmt.Println("conf.sigBits: ", *confRepo.sigBits)
	fmt.Println("conf.encAlg: ", *confRepo.encAlg)
	fmt.Println("conf.encBits: ", *confRepo.encBits)
	fmt.Println("conf.selfName: ", *confRepo.selfName)
	fmt.Println("conf.password: ", *confRepo.password)
	fmt.Println("conf.dbPath: ", *confRepo.dbPath)
}

func (o options) validate() error {
	return nil
}

// func (o *options) store() error {
// 	bkt := buckets["internalBucketName"]
// 	ShouldSet(bkt, confListen, []byte(*conf.listen))
// 	ShouldSet(bkt, confTLS, strconv.AppendBool([]byte{}, *conf.tls))
// 	ShouldSet(bkt, confSigAlg, []byte(*conf.sigAlg))
// 	ShouldSet(bkt, confSigBits, strconv.AppendInt([]byte{}, int64(*conf.sigBits), 10))
// 	ShouldSet(bkt, confEncAlg, []byte(*conf.encAlg))
// 	ShouldSet(bkt, confEncBits, strconv.AppendInt([]byte{}, int64(*conf.encBits), 10))
// 	ShouldSet(bkt, confSelfName, []byte(*conf.selfName))
// 	ShouldSet(bkt, confPassword, []byte(*conf.password))
// 	ShouldSet(bkt, confDbPath, []byte(*conf.dbPath))

// 	ShouldSet(bkt, dbCheckKey, dbCheckValue)
// 	return nil
// }

// func (o *options) load() error {
// 	bkt := buckets["internalBucketName"]
// 	if dbExists && !conf.listenSetByUser {
// 		*conf.listen = string(ShouldGet(bkt, confListen)) //, []byte(*conf.listen))
// 	}
// 	var err error
// 	if dbExists && !conf.tlsSetByUser {
// 		tls := ShouldGet(bkt, confTLS)
// 		if *conf.tls, err = strconv.ParseBool(string(tls)); err != nil {
// 			return err
// 		}
// 	}
// 	if dbExists && !conf.sigAlgSetByUser {
// 		*conf.sigAlg = string(ShouldGet(bkt, confSigAlg)) //, []byte(*conf.sigAlg))
// 	}
// 	if dbExists && !conf.sigBitsSetByUser {
// 		sbits := ShouldGet(bkt, confSigBits)
// 		if *conf.sigBits, err = strconv.Atoi(string(sbits)); err != nil {
// 			return nil
// 		}
// 	}
// 	if dbExists && !conf.encAlgSetByUser {
// 		*conf.encAlg = string(ShouldGet(bkt, confEncAlg)) //, []byte(*conf.encAlg))
// 	}
// 	if dbExists && !conf.encBitsSetByUser {
// 		ebits := ShouldGet(bkt, confEncBits)
// 		if *conf.encBits, err = strconv.Atoi(string(ebits)); err != nil {
// 			return nil
// 		}
// 	}
// 	if dbExists && !conf.selfNameSetByUser {
// 		*conf.selfName = string(ShouldGet(bkt, confSelfName)) //, []byte(*conf.selfName))
// 	}
// 	if dbExists && !conf.passwordSetByUser {
// 		*conf.password = string(ShouldGet(bkt, confPassword)) //, []byte(*conf.password))
// 	}
// 	if dbExists && !conf.dbPathSetByUser {
// 		*conf.dbPath = string(ShouldGet(bkt, confDbPath)) //, []byte(*conf.dbPath))
// 	}
// 	return nil
// }

func checkDbPath() {
	dir, _ := filepath.Split(*confRepo.dbPath)
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
