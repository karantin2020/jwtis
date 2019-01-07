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

type configRepository struct {
	defaults
	options
	repoDB     *bolt.DB
	bucketName []byte
	bucketKeys [][]byte
}

func initConfigRepository(db *bolt.DB) configRepository {
	repo := configRepository{
		repoDB: db,
		defaults: defaults{
			defListen:   "127.0.0.1:4343",
			defTLS:      false,
			defSigAlg:   "RS256",
			defSigBits:  2048,
			defEncAlg:   "RSA-OAEP-256",
			defEncBits:  2048,
			defSelfName: "JWTIS",
			defPassword: "",
			defDbPath:   "./data/" + dbPathName,
		},
		bucketName: buckets["configBucketName"],
		bucketKeys: [][]byte{
			[]byte("jwtis.conf.listen"),
			[]byte("jwtis.conf.tls"),
			[]byte("jwtis.conf.sigAlg"),
			[]byte("jwtis.conf.sigBits"),
			[]byte("jwtis.conf.encAlg"),
			[]byte("jwtis.conf.encBits"),
			[]byte("jwtis.conf.selfName"),
			[]byte("jwtis.conf.password"),
			[]byte("jwtis.conf.dbPath"),
		},
	}
	return repo
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

func (p *configRepository) setDB(db *bolt.DB) *configRepository {
	p.repoDB = db
	return p
}

func (p *configRepository) save() error {
	if p.repoDB == nil {
		return errDBNotSet
	}
	if err := boltDB.Batch(func(tx *bolt.Tx) error {
		b := tx.Bucket(p.bucketName)
		if err := save(b, confListen, p.listen); err != nil { //= string(ShouldGet(bkt, confListen)) //, []byte(*conf.listen))
			return err
		}
		return nil
	}); err != nil {
		return errSaveDBConf
	}
	return nil
}

func (p *configRepository) load() error {
	if p.repoDB == nil {
		return errDBNotSet
	}
	if err := boltDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(p.bucketName)
		if !p.listenSetByUser {
			if err := load(b, confListen, p.listen); err != nil { //= string(ShouldGet(bkt, confListen)) //, []byte(*conf.listen))
				return err
			}
		}
		return nil
	}); err != nil {
		return errLoadDBConf
	}
	return nil
}
