package main

import (
	"fmt"

	bolt "github.com/coreos/bbolt"
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
	p.defSigAlg = "RS256"
	p.defSigBits = 2048
	p.defEncAlg = "ECDH-ES+A256KW"
	p.defEncBits = 521
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
	p.expiry = &p.defExpiry
	p.authTTL = &p.defAuthTTL
	p.refreshTTL = &p.defRefreshTTL
	p.selfName = &p.defSelfName
	p.password = &p.defPassword
	p.dbPath = &p.defDbPath
	return p
}

func (p configRepository) validate() error {
	var mErr jwtis.Error

	switch *p.sigAlg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		if *p.sigBits != 0 && *p.sigBits < 2048 {
			mErr.Append(errInvalidSigBitsValue)
		}
	case "ES256", "ES384", "ES512", "EdDSA":
		if !containsInt(bits, *p.sigBits) {
			mErr.Append(errInvalidSigBitsValueA)
		}
	default:
		mErr.Append(errInvalidSigConfig)
	}

	switch *p.encAlg {
	case "RSA1_5", "RSA-OAEP", "RSA-OAEP-256":
		if *p.encBits != 0 && *p.encBits < 2048 {
			mErr.Append(errInvalidEncBitsValue)
		}
	case "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW":
		if !containsInt(bits, *p.encBits) {
			mErr.Append(errInvalidEncBitsValueA)
		}
	default:
		mErr.Append(errInvalidEncConfig)
	}
	if len(mErr) != 0 {
		return mErr
	}
	return nil
}

var (
	sigAlgs = []string{"ES256", "ES384", "ES512", "EdDSA", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}
	encAlgs = []string{"RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"}
	bits    = []int{0, 256, 384, 521}
)

var (
	errInvalidEncBitsValue  = fmt.Errorf("too short enc key for RSA `alg`, 2048+ is required")
	errInvalidEncBitsValueA = fmt.Errorf("this enc `alg` does not support arbitrary key length")
	errInvalidEncConfig     = fmt.Errorf("invalid encrypt config flags")
	errInvalidSigBitsValue  = fmt.Errorf("too short sig key for RSA `alg`, 2048+ is required")
	errInvalidSigBitsValueA = fmt.Errorf("this sig `alg` does not support arbitrary key length")
	errInvalidSigConfig     = fmt.Errorf("invalid sign config flags")
)

func containsString(l []string, s string) bool {
	for i := range l {
		if l[i] == s {
			return true
		}
	}
	return false
}

func containsInt(l []int, s int) bool {
	for i := range l {
		if l[i] == s {
			return true
		}
	}
	return false
}
