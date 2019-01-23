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
	contEnc *string // Default Content Encryption
}
type jwtttl struct {
	authTTL    *string // Default value for auth jwt ttl
	refreshTTL *string // Default value for refresh jwt ttl
}
type keyGeneration struct {
	// keys generation options
	sign
	encryption
	expiry *string
	jwtttl
}
type setByUser struct {
	listenSetByUser     bool
	tlsSetByUser        bool
	sigAlgSetByUser     bool
	sigBitsSetByUser    bool
	encAlgSetByUser     bool
	encBitsSetByUser    bool
	contEncSetByUser    bool
	expirySetByUser     bool
	authTTLSetByUser    bool
	refreshTTLSetByUser bool
	selfNameSetByUser   bool
	passwordSetByUser   bool
	dbPathSetByUser     bool
	VerboseSetByUser    bool
}
type defaults struct {
	defListen     string
	defTLS        bool
	defSigAlg     string
	defSigBits    int
	defEncAlg     string
	defEncBits    int
	defContEnc    string
	defExpiry     string
	defAuthTTL    string
	defRefreshTTL string
	defSelfName   string
	defPassword   string
	defDbPath     string
	defVerbose    bool
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
	p.defSigAlg = "ES256"
	p.defSigBits = 256
	p.defEncAlg = "ECDH-ES+A256KW"
	p.defEncBits = 256
	p.defContEnc = "A256GCM"
	p.defExpiry = "4320h"    // 180 days
	p.defAuthTTL = "72h"     // 3 days
	p.defRefreshTTL = "720h" // 30 days
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
	p.contEnc = &p.defContEnc
	p.expiry = &p.defExpiry
	p.authTTL = &p.defAuthTTL
	p.refreshTTL = &p.defRefreshTTL
	p.selfName = &p.defSelfName
	p.password = &p.defPassword
	p.dbPath = &p.defDbPath
	return p
}

func (p configRepository) validate() error {
	return nil
}
