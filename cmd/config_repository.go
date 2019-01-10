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
}

func (p *configRepository) init(db *bolt.DB) {
	if p == nil {
		panic("configRepository pointer is nil")
	}
	p.repoDB = db
	p.defListen = "127.0.0.1:4343"
	p.defTLS = false
	p.defSigAlg = "RS256"
	p.defSigBits = 2048
	p.defEncAlg = "RSA-OAEP-256"
	p.defEncBits = 2048
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
		if err := save(b, confListen, p.listen); err != nil {
			return err
		}
		if err := save(b, confTLS, p.tls); err != nil {
			return err
		}
		if err := save(b, confSigAlg, p.sigAlg); err != nil {
			return err
		}
		if err := save(b, confSigBits, p.sigBits); err != nil {
			return err
		}
		if err := save(b, confEncAlg, p.encAlg); err != nil {
			return err
		}
		if err := save(b, confEncBits, p.encBits); err != nil {
			return err
		}
		if err := save(b, confSelfName, p.selfName); err != nil {
			return err
		}
		if err := save(b, confPassword, p.password); err != nil {
			return err
		}
		if err := save(b, confDbPath, p.dbPath); err != nil {
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
			if err := load(b, confListen, p.listen); err != nil {
				return err
			}
		}
		if !p.tlsSetByUser {
			if err := load(b, confTLS, p.tls); err != nil {
				return err
			}
		}
		if !p.sigAlgSetByUser {
			if err := load(b, confSigAlg, p.sigAlg); err != nil {
				return err
			}
		}
		if !p.sigBitsSetByUser {
			if err := load(b, confSigBits, p.sigBits); err != nil {
				return err
			}
		}
		if !p.encAlgSetByUser {
			if err := load(b, confEncAlg, p.encAlg); err != nil {
				return err
			}
		}
		if !p.encBitsSetByUser {
			if err := load(b, confEncBits, p.encBits); err != nil {
				return err
			}
		}
		if !p.selfNameSetByUser {
			if err := load(b, confSelfName, p.selfName); err != nil {
				return err
			}
		}
		if !p.passwordSetByUser {
			if err := load(b, confPassword, p.password); err != nil {
				return err
			}
		}
		if !p.dbPathSetByUser {
			if err := load(b, confDbPath, p.dbPath); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return errLoadDBConf
	}
	return nil
}
