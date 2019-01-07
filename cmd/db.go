package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"time"

	bolt "github.com/coreos/bbolt"
)

func openDB() (*bolt.DB, error) {
	opts := &bolt.Options{Timeout: 10 * time.Second}
	db, err := bolt.Open(*conf.dbPath, 0600, opts)
	if err != nil {
		return nil, fmt.Errorf("couldn't open keys db: %s", err.Error())
	}
	err = db.Update(func(tx *bolt.Tx) error {
		if _, e := tx.CreateBucketIfNotExists(keysBucketName); e != nil {
			return fmt.Errorf("failed to create top level bucket %s, error: %s", keysBucketName, e.Error())
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create top level bucket: %s", err.Error())
	}
	dbExists = true
	return db, nil
}

func checkDBPassword() {
	val, err := Get(dbCheckKey)
	if err != nil {
		log.Printf("error getting dbCheckKey: %s\n", err.Error())
	}
	if val == nil {
		log.Printf("DB has no dbCheckValue, use generated password\n")
		*conf.password = getPassword(passwordLength)
		log.Printf("generated conf.password: '%s'\n", *conf.password)
		dbExists = false
		dbCheckFault = false
		return
	} else if !bytes.Equal(val, dbCheckValue) {
		dbExists = true
		dbCheckFault = true
		FatalF("prompted password is not equal to db password\n")
	} else {
		dbExists = true
		dbCheckFault = false
	}
}

func newDBPassword() {
	log.Printf("DB password check didn't pass, use generated password\n")
	*conf.password = getPassword(passwordLength)
	log.Printf("generated password: '%s'\n", *conf.password)
}

// ====== Should Methods ========= //

// ShouldGet value from badger
func ShouldGet(k []byte) []byte {
	v, _ := Get(k)
	if v == nil {
		return []byte{}
	}
	return v
}

// ShouldExists checks if the key exists in db
func ShouldExists(k []byte) bool {
	v, _ := Exists(k)
	return v
}

// ShouldSet the key in badger
func ShouldSet(k []byte, v []byte) {
	if err := Set(k, v); err != nil {
		FatalF("%s\n", err.Error())
	}
}

// ShouldDelete key/value pair from db
func ShouldDelete(k []byte) {
	err := Delete(k)
	if err != nil {
		FatalF("%s\n", err.Error())
	}
}

// ====== Pure Error Methods ========= //

// Get value from badger
func Get(k []byte) ([]byte, error) {
	var value []byte
	err := boltDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(keysBucketName)
		v := b.Get(k)
		value = append(value, v...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("couldn't get key/value with value '%s' : %s",
			string(k), err.Error())
	}
	return value, nil
}

// Exists checks if the key exists in db
func Exists(k []byte) (bool, error) {
	exist := false
	err := boltDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(keysBucketName)
		v := b.Get(k)
		exist = v != nil
		return nil
	})
	return exist, err
}

// Set the key in badger
func Set(k []byte, v []byte) error {
	return boltDB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(keysBucketName)
		return b.Put(k, v)
	})
}

// Delete key/value pair from db
func Delete(k []byte) error {
	return boltDB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(keysBucketName)
		return b.Delete(k)
	})
}

// ====== BoltDB methods ======= //

// save marshaled value to key for bucket. Should run in update tx
func save(bkt *bolt.Bucket, key []byte, value interface{}) (err error) {
	if value == nil {
		return fmt.Errorf("can't save nil value for %s", string(key))
	}
	jdata, jerr := json.Marshal(value)
	if jerr != nil {
		return fmt.Errorf("can't marshal comment: %s", jerr.Error())
	}
	if err = bkt.Put(key, jdata); err != nil {
		return fmt.Errorf("failed to save key %s, error: %s", string(key), err.Error())
	}
	return nil
}

// load and unmarshal json value by key from bucket. Should run in view tx
func load(bkt *bolt.Bucket, key []byte, res interface{}) error {
	value := bkt.Get(key)
	if value == nil {
		return fmt.Errorf("no value for %s", string(key))
	}

	if err := json.Unmarshal(value, &res); err != nil {
		return fmt.Errorf("failed to unmarshal: %s", err.Error())
	}
	return nil
}
