package main

import (
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
)

const (
	dbPathName = "keys.db" // default db folder name
)

func newConfigApp() *cli.Cli {
	app := cli.App(appName, appDescription)
	app.Version("V version", appVersion)
	app.Spec = "[OPTIONS]"
	confRepo.init(nil)
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
		Desc:      "Default algorithn to be used for sign. Possible values are: ES256 ES384 ES512 EdDSA RS256 RS384 RS512 PS256 PS384 PS512",
		EnvVar:    envPrefix + "SIG_ALG",
		SetByUser: &confRepo.sigAlgSetByUser,
	})
	confRepo.sigBits = app.Int(cli.IntOpt{
		Name:      "sigBits",
		Value:     confRepo.defSigBits,
		Desc:      "Default key size in bits for sign key. Supported elliptic bit lengths are 256, 384, 521",
		EnvVar:    envPrefix + "SIG_BITS",
		SetByUser: &confRepo.sigBitsSetByUser,
	})
	confRepo.encAlg = app.String(cli.StringOpt{
		Name:      "encAlg",
		Value:     confRepo.defEncAlg,
		Desc:      "Default algorithn to be used for encrypt. Possible values are RSA1_5 RSA-OAEP RSA-OAEP-256 ECDH-ES ECDH-ES+A128KW ECDH-ES+A192KW ECDH-ES+A256KW",
		EnvVar:    envPrefix + "ENC_ALG",
		SetByUser: &confRepo.encAlgSetByUser,
	})
	confRepo.encBits = app.Int(cli.IntOpt{
		Name:      "encBits",
		Value:     confRepo.defEncBits,
		Desc:      "Default key size in bits for encrypt. Supported elliptic bit lengths are 256, 384, 521",
		EnvVar:    envPrefix + "ENC_BITS",
		SetByUser: &confRepo.encBitsSetByUser,
	})
	confRepo.contEnc = app.String(cli.StringOpt{
		Name:      "contEnc",
		Value:     confRepo.defContEnc,
		Desc:      "Default content encryption. Possible values are A128GCM, A192GCM, A256GCM",
		EnvVar:    envPrefix + "CONT_ENC",
		SetByUser: &confRepo.contEncSetByUser,
	})
	confRepo.expiry = app.String(cli.StringOpt{
		Name:      "e expiry",
		Value:     confRepo.defExpiry,
		Desc:      "Default keys time to live, expiration time [Duration string]",
		EnvVar:    envPrefix + "EXPIRY",
		SetByUser: &confRepo.expirySetByUser,
	})
	confRepo.authTTL = app.String(cli.StringOpt{
		Name:      "a authTTL",
		Value:     confRepo.defAuthTTL,
		Desc:      "Default auth JWT token time to live, expiration time [Duration string]",
		EnvVar:    envPrefix + "AUTH_TTL",
		SetByUser: &confRepo.authTTLSetByUser,
	})
	confRepo.refreshTTL = app.String(cli.StringOpt{
		Name:      "r refreshTTL",
		Value:     confRepo.defRefreshTTL,
		Desc:      "Default refresh JWT token time to live, expiration time [Duration string]",
		EnvVar:    envPrefix + "REFRESH_TTL",
		SetByUser: &confRepo.refreshTTLSetByUser,
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
	confRepo.verbose = app.Bool(cli.BoolOpt{
		Name:      "v verbose",
		Value:     confRepo.defVerbose,
		Desc:      "Verbose. Show detailed logs",
		EnvVar:    envPrefix + "VERBOSE",
		SetByUser: &confRepo.VerboseSetByUser,
	})
	return app
}

func (o options) validate() error {
	return nil
}

// password: getPassword(passwordLength), // Storage password generated by this app
func getPassword(length int) []byte {
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
	return secret
}

// FatalF prints message to log and then interrupts app execution
func FatalF(format string, v ...interface{}) {
	log.Error().Msgf(format, v...)
	cli.Exit(1)
}
