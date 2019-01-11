package jwtis

import (
	"encoding/json"
	"errors"
	"fmt"

	bolt "github.com/coreos/bbolt"
)

var (
	// ErrKeyNotFound describes error when looking key is not found in db
	ErrKeyNotFound = errors.New("requested key was not found in db")
)

// save marshaled value to key for bucket. Should run in update tx
func save(bkt *bolt.Bucket, key []byte, value interface{}) (err error) {
	if value == nil {
		return fmt.Errorf("can't save nil value for %s", string(key))
	}
	jdata, jerr := json.Marshal(value)
	if jerr != nil {
		return fmt.Errorf("can't marshal value: %s", jerr.Error())
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
		return ErrKeyNotFound
	}

	if err := json.Unmarshal(value, &res); err != nil {
		return fmt.Errorf("failed to unmarshal: %s", err.Error())
	}
	return nil
}

func exists(db *bolt.DB, bkt, k []byte) (bool, error) {
	if k == nil {
		return false, fmt.Errorf("nil key %s", string(k))
	}
	exist := false
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bkt)
		v := b.Get(k)
		exist = v != nil
		return nil
	})
	return exist, err
}
