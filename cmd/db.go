package main

import (
	"github.com/dgraph-io/badger"
)

func openDB() *badger.DB {
	opts := badger.DefaultOptions
	opts.Dir = *conf.dbPath
	opts.ValueDir = *conf.dbPath
	if db, err := badger.Open(opts); err != nil {
		defer db.Close()
		FatalF("Couldn't open keys db: %s", err.Error())
	}
	return db
}
