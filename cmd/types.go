package main

type keyVal struct {
	key []byte
	val []byte
}

type keyValAny struct {
	key []byte
	val interface{}
	s   *bool
}
