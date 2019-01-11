package main

import (
	"bytes"
	"fmt"

	bolt "github.com/coreos/bbolt"
	"github.com/karantin2020/jwtis"

	cli "github.com/jawher/mow.cli"
)

// http config
type configs struct {
	Listen   string // ip:port to listen to
	TLS      bool   // Future feature
	SigAlg   string // Default algorithn to be used for sign
	SigBits  int    // Default key size in bits for sign
	EncAlg   string // Default algorithn to be used for encrypt
	EncBits  int    // Default key size in bits for encrypt
	SelfName []byte
}

type internalVars struct {
	dbCheckValue []byte
	password     []byte
	nonce        []byte
	encKey       jwtis.Key
}

type internalRepository struct {
	// configs
	configs

	internalVars
	repoDB     *bolt.DB
	confRepo   *configRepository
	bucketName []byte
}

type nonceCheck struct {
	Nonce    []byte
	CheckKey []byte
}

type mackey struct {
	jwtis.MACKey `json:"mac"`
}

var (
	internalPassword = []byte("jwtis.internal.password")
	internalNonce    = []byte("jwtis.internal.nonce")
	internalEncKey   = []byte("jwtis.internal.enckey")
	internalConfigs  = []byte("jwtis.internal.configs")
	dbCheckKey       = []byte("jwtis.conf.dbCheckKey")
	dbCheckValue     = []byte("jwtis.conf.dbCheckValue")
	dbExists         bool
	dbCheckFault     bool
)

func (p *internalRepository) init(db *bolt.DB, confRepo *configRepository) {
	if p == nil {
		log.Info().Msg("internalRepository pointer is nil")
		cli.Exit(1)
	}
	if db == nil {
		log.Info().Msg("internalRepository db pointer is nil")
		cli.Exit(1)
	}
	if confRepo == nil {
		log.Info().Msg("internalRepository confRepo pointer is nil")
		cli.Exit(1)
	}
	p.bucketName = buckets["internalBucketName"]
	p.repoDB = db
	p.confRepo = confRepo
	p.setPassword([]byte(*confRepo.password))

	if err := p.load(); err != nil {
		log.Error().Err(err).Msg("can't load internalRepo from boltDB; exit")
		cli.Exit(1)
	}

	if !dbExists || confRepo.selfNameSetByUser {
		p.SelfName = []byte(*confRepo.selfName)
	}
	if !dbExists || confRepo.listenSetByUser {
		p.Listen = *confRepo.listen
	}
	if !dbExists || confRepo.tlsSetByUser {
		p.TLS = *confRepo.tls
	}
	if !dbExists || confRepo.sigAlgSetByUser {
		p.SigAlg = *confRepo.sigAlg
	}
	if !dbExists || confRepo.sigBitsSetByUser {
		p.SigBits = *confRepo.sigBits
	}
	if !dbExists || confRepo.encAlgSetByUser {
		p.EncAlg = *confRepo.encAlg
	}
	if !dbExists || confRepo.encBitsSetByUser {
		p.EncBits = *confRepo.encBits
	}
	if err := p.save(); err != nil {
		log.Error().Err(err).Msg("can't save internalRepo; exit")
		cli.Exit(1)
	}
}

func (p internalRepository) printConfigs() {
	fmt.Printf("Configs found:\n")
	fmt.Println("internalRepo.configs.listen: ", p.Listen)
	fmt.Println("internalRepo.configs.tls: ", p.TLS)
	fmt.Println("internalRepo.configs.sigAlg: ", p.SigAlg)
	fmt.Println("internalRepo.configs.sigBits: ", p.SigBits)
	fmt.Println("internalRepo.configs.encAlg: ", p.EncAlg)
	fmt.Println("internalRepo.configs.encBits: ", p.EncBits)
	fmt.Println("internalRepo.configs.selfName: ", string(p.SelfName))
	fmt.Printf("internalRepo.configs.password: '%s'\n", string(p.password))
	fmt.Println("conf.dbPath: ", *confRepo.dbPath)
}

func (p internalRepository) validate() error {
	return nil
}

func (p *internalRepository) setDB(db *bolt.DB) *internalRepository {
	p.repoDB = db
	return p
}

func (p *internalRepository) setPassword(psw []byte) *internalRepository {
	p.password = append(p.password[:0], psw...)
	copy(p.encKey.EncryptionKey[:], []byte(psw))
	return p
}

func (p *internalRepository) save() error {
	if p.repoDB == nil {
		return errDBNotSet
	}
	if err := boltDB.Batch(func(tx *bolt.Tx) error {
		b := tx.Bucket(p.bucketName)
		key := mackey{
			MACKey: p.encKey.MACKey,
		}
		if err := save(b, internalEncKey, key); err != nil {
			return err
		}
		buf := make([]byte, 0, len(dbCheckValue)+jwtis.Extension+len(p.nonce))
		ciphertext := p.encKey.Seal(buf[:0], p.nonce, dbCheckValue, nil)
		nk := append(append([]byte{}, p.nonce...), ciphertext...)
		if err := saveByte(b, dbCheckKey, nk); err != nil {
			return err
		}
		if err := save(b, internalConfigs, p.configs); err != nil {
			return err
		}
		// log.Printf("saved internal configs: '%+v'\n", p.configs)
		return nil
	}); err != nil {
		return fmt.Errorf("%s: %s", errSaveDBInternal.Error(), err.Error())
	}
	return nil
}

func (p *internalRepository) load() error {
	if p.repoDB == nil {
		return errDBNotSet
	}
	dbExists = true
	// log.Printf("enc key is: '%+v'", p.encKey)
	// log.Printf("enc key secret is: '%s'", string(p.encKey.EncryptionKey[:]))
	if err := boltDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(p.bucketName)
		if err := load(b, internalEncKey, &p.encKey); err != nil {
			if err == errKeyNotFound {
				return errEncKeyNotFound
			}
			return err
		}
		// log.Printf("loaded enc key is: '%+v'", p.encKey)
		nk := []byte{}
		if err := loadByte(b, dbCheckKey, &nk); err != nil {
			if err == errKeyNotFound {
				return errCheckKeyNotFound
			}
			return fmt.Errorf("error loading dbCheckValue: %s", err.Error())
		}
		nonce, ciphertext := nk[:p.encKey.NonceSize()], nk[p.encKey.NonceSize():]
		plaintext, err := p.encKey.Open(ciphertext[:0], nonce, ciphertext, nil)
		if err != nil {
			return err
		}
		p.dbCheckValue = append([]byte{}, plaintext...)
		p.nonce = append([]byte{}, nonce...)
		if err := load(b, internalConfigs, &p.configs); err != nil {
			return fmt.Errorf("error loading internalConfigs: %s", err.Error())
		}
		// log.Printf("loaded internal configs: '%+v'\n", p.configs)
		return nil
	}); err != nil {
		if err != errCheckKeyNotFound && err != errEncKeyNotFound {
			if err == jwtis.ErrInvalidEncKey && *p.confRepo.password == "" {
				FatalF("db password must be inserted")
			}
			return fmt.Errorf("%s: %s", errLoadDBInternal.Error(), err.Error())
		}
		dbExists = false
		newDBPassword()
	}
	if dbExists && !bytes.Equal(p.dbCheckValue, dbCheckValue) {
		// log.Printf("p.dbCheckValue is: '%s'\n", p.dbCheckValue)
		// log.Printf("dbCheckValue is: '%s'\n", dbCheckValue)
		FatalF(errIncorrectPassword.Error())
	}
	return nil
}

func newDBPassword() {
	log.Info().Msg("generate new db password\n")
	internalsRepo.password = getPassword(passwordLength)
	log.Info().Msgf("generated password is: '%s'\n", string(internalsRepo.password))
	internalsRepo.nonce = jwtis.NewRandomNonce()
	internalsRepo.encKey.Init()
	if len(internalsRepo.encKey.EncryptionKey) != len(internalsRepo.password) {
		FatalF("wrong lengths of internalsRepo.encKey.EncryptionKey or internalsRepo.password\n")
	}
	copy(internalsRepo.encKey.EncryptionKey[:], internalsRepo.password)
}
