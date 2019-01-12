package main

import (
	bolt "github.com/coreos/bbolt"
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
	VerboseSetByUser  bool
}
type defaults struct {
	defListen   string
	defTLS      bool
	defSigAlg   string
	defSigBits  int
	defEncAlg   string
	defEncBits  int
	defSelfName string
	defPassword string
	defDbPath   string
	defVerbose  bool
}
type options struct {
	httpConf
	keyGeneration
	selfName *string // Name of this service

	// internal options
	password *string // Storage password. App generates password with db creation.
	// Later user must provide a password to access the database
	dbPath  *string
	verbose *bool
	setByUser
}

type configRepository struct {
	defaults
	options
	bucketName []byte
}

func (p *configRepository) init(db *bolt.DB) {
	if p == nil {
		panic("configRepository pointer is nil")
	}
	p.defListen = "127.0.0.1:4343"
	p.defTLS = false
	p.defSigAlg = "RS256"
	p.defSigBits = 2048
	p.defEncAlg = "ECDH-ES+A256KW"
	p.defEncBits = 521
	p.defSelfName = "JWTIS"
	p.defPassword = ""
	p.defDbPath = "./data/" + dbPathName
	p.bucketName = buckets["configBucketName"]
	p.setDefaults()
}

func (p *configRepository) setDefaults() *configRepository {
	p.listen = &p.defListen
	p.tls = &p.defTLS
	p.sigAlg = &p.defSigAlg
	p.sigBits = &p.defSigBits
	p.encAlg = &p.defEncAlg
	p.encBits = &p.defEncBits
	p.selfName = &p.defSelfName
	p.password = &p.defPassword
	p.dbPath = &p.defDbPath
	return p
}

func (p configRepository) validate() error {
	return nil
}
