package main

import (
	"bytes"
	"fmt"
	"log"

	bolt "github.com/coreos/bbolt"
)

type internalVars struct {
	dbCheckKey   []byte
	dbCheckValue []byte
	password     []byte
}

type internalRepository struct {
	internalVars
	repoDB     *bolt.DB
	bucketName []byte
	bucketKeys [][]byte
}

var (
	internalPassword = []byte("jwtis.internal.password")
)

func initInternalRepository(db *bolt.DB) internalRepository {
	internal := internalRepository{
		bucketName: buckets["internalBucketName"],
		bucketKeys: [][]byte{
			[]byte("jwtis.internal.dbCheckKey"),
			[]byte("jwtis.internal.password"),
		},
	}
	internal.dbCheckKey = dbCheckKey
	internal.dbCheckValue = dbCheckValue
	return internal
}

func (p internalRepository) validate() error {
	return nil
}

func (p *internalRepository) setDB(db *bolt.DB) *internalRepository {
	p.repoDB = db
	return p
}

func (p *internalRepository) save() error {
	if p.repoDB == nil {
		return errDBNotSet
	}
	if err := boltDB.Batch(func(tx *bolt.Tx) error {
		b := tx.Bucket(p.bucketName)
		if err := save(b, p.dbCheckKey, p.dbCheckValue); err != nil { //= string(ShouldGet(bkt, confListen)) //, []byte(*conf.listen))
			return err
		}
		if err := save(b, internalPassword, &p.password); err != nil { //= string(ShouldGet(bkt, confListen)) //, []byte(*conf.listen))
			return err
		}
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
	if err := boltDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(p.bucketName)
		if err := load(b, p.dbCheckKey, p.dbCheckValue); err != nil { //= string(ShouldGet(bkt, confListen)) //, []byte(*conf.listen))
			if err == errKeyNotFound {
				dbExists = false
				dbCheckFault = false
			} else {
				return err
			}
		}
		if err := load(b, internalPassword, &p.password); err != nil { //= string(ShouldGet(bkt, confListen)) //, []byte(*conf.listen))
			if err != errKeyNotFound {
				return err
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("%s : %s", errLoadDBInternal.Error(), err.Error())
	}
	if !dbExists {
		newDBPassword()
	} else if !bytes.Equal(internalsRepo.dbCheckValue, dbCheckValue) {
		dbExists = true
		dbCheckFault = true
		FatalF("prompted password is not equal to db password\n")
	} else {
		dbExists = true
		dbCheckFault = false
	}
	return nil
}

func newDBPassword() {
	log.Printf("DB password check didn't pass, use generated password\n")
	*confRepo.password = getPassword(passwordLength)
	log.Printf("generated password: '%s'\n", *confRepo.password)
	internalsRepo.password = append(internalsRepo.password[:0], []byte(*confRepo.password)...)
}
