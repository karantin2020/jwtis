package main

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "github.com/coreos/bbolt"
)

func openDB() (*bolt.DB, error) {
	opts := &bolt.Options{Timeout: 10 * time.Second}
	db, err := bolt.Open(*confRepo.dbPath, 0600, opts)
	if err != nil {
		return nil, fmt.Errorf("couldn't open keys db: %s", err.Error())
	}
	for _, v := range buckets {
		err = db.Update(func(tx *bolt.Tx) error {
			if _, e := tx.CreateBucketIfNotExists(v); e != nil {
				return fmt.Errorf("failed to create top level bucket %s, error: %s", v, e.Error())
			}
			return nil
		})
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create top level bucket: %s", err.Error())
	}
	dbExists = true
	return db, nil
}

// ====== Should Methods ========= //

// ShouldGet value from bboltdb
func ShouldGet(bkt, k []byte) []byte {
	v, _ := Get(bkt, k)
	if v == nil {
		return []byte{}
	}
	return v
}

// ShouldExists checks if the key exists in db
func ShouldExists(bkt, k []byte) bool {
	v, _ := Exists(bkt, k)
	return v
}

// ShouldSet the key in bboltdb
func ShouldSet(bkt, k, v []byte) {
	if err := Set(bkt, k, v); err != nil {
		FatalF("%s\n", err.Error())
	}
}

// ShouldDelete key/value pair from db
func ShouldDelete(bkt, k []byte) {
	err := Delete(bkt, k)
	if err != nil {
		FatalF("%s\n", err.Error())
	}
}

// ====== Pure Error Methods ========= //

// Get value from bboltdb
func Get(bkt, k []byte) ([]byte, error) {
	if k == nil {
		return nil, fmt.Errorf("nil key %s", string(k))
	}
	var value []byte
	err := boltDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bkt)
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
func Exists(bkt, k []byte) (bool, error) {
	if k == nil {
		return false, fmt.Errorf("nil key %s", string(k))
	}
	exist := false
	err := boltDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bkt)
		v := b.Get(k)
		exist = v != nil
		return nil
	})
	return exist, err
}

// Set the key in bboltdb
func Set(bkt, k, v []byte) error {
	if k == nil {
		return fmt.Errorf("nil key %s", string(k))
	}
	if v == nil {
		return fmt.Errorf("nil val for key %s", string(k))
	}
	return boltDB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bkt)
		return b.Put(k, v)
	})
}

// Delete key/value pair from db
func Delete(bkt, k []byte) error {
	if k == nil {
		return fmt.Errorf("nil key %s", string(k))
	}
	return boltDB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bkt)
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
		return errKeyNotFound
	}

	if err := json.Unmarshal(value, &res); err != nil {
		return fmt.Errorf("failed to unmarshal: %s", err.Error())
	}
	return nil
}

// saveByte puts val into bucket. []byte version
func saveByte(bkt *bolt.Bucket, key, val []byte) (err error) {
	if val == nil {
		return fmt.Errorf("can't save nil value for %s", string(key))
	}
	if err = bkt.Put(key, val); err != nil {
		return fmt.Errorf("failed to save key %s, error: %s", string(key), err.Error())
	}
	return nil
}

// loadByte gets val from bucket. []byte version
func loadByte(bkt *bolt.Bucket, key, val []byte) error {
	value := bkt.Get(key)
	if value == nil {
		return fmt.Errorf("no value for %s", string(key))
	}

	val = val[:0]
	val = append(val, value...)
	return nil
}
