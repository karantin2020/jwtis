// Copy from https://github.com/square/go-jose/jwk-keygen
// Code author is Square Inc.
//
// Licensed under the Apache License, Version 2.0

package jwtis

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"golang.org/x/crypto/ed25519"

	jose "gopkg.in/square/go-jose.v2"
)

var (
	// SigAlgs is array of possible sig algorithms
	SigAlgs = []string{
		string(jose.ES256), string(jose.ES384), string(jose.ES512),
		string(jose.EdDSA), string(jose.RS256), string(jose.RS384),
		string(jose.RS512), string(jose.PS256), string(jose.PS384),
		string(jose.PS512),
	}
	// EncAlgs is array of possible enc algorithms
	EncAlgs = []string{
		string(jose.RSA1_5), string(jose.RSA_OAEP),
		string(jose.RSA_OAEP_256), string(jose.ECDH_ES),
		string(jose.ECDH_ES_A128KW), string(jose.ECDH_ES_A192KW),
		string(jose.ECDH_ES_A256KW),
	}
	// Use is array of possible use values
	Use = []string{
		"enc", "sig",
	}
)

// PrivPubKeySet holds private and public keys
type PrivPubKeySet struct {
	Priv jose.JSONWebKey
	Pub  jose.JSONWebKey
}

// KeygenSig generates keypair for corresponding SignatureAlgorithm.
func KeygenSig(alg jose.SignatureAlgorithm, bits int) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch alg {
	case jose.ES256, jose.ES384, jose.ES512, jose.EdDSA:
		keylen := map[jose.SignatureAlgorithm]int{
			jose.ES256: 256,
			jose.ES384: 384,
			jose.ES512: 521, // sic!
			jose.EdDSA: 256,
		}
		if bits != 0 && bits != keylen[alg] {
			return nil, nil, errors.New("this `alg` does not support arbitrary key length")
		}
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		if bits == 0 {
			bits = 2048
		}
		if bits < 2048 {
			return nil, nil, errors.New("too short key for RSA `alg`, 2048+ is required")
		}
	}
	switch alg {
	case jose.ES256:
		// The cryptographic operations are implemented using constant-time algorithms.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return key.Public(), key, err
	case jose.ES384:
		// NB: The cryptographic operations do not use constant-time algorithms.
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		return key.Public(), key, err
	case jose.ES512:
		// NB: The cryptographic operations do not use constant-time algorithms.
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		return key.Public(), key, err
	case jose.EdDSA:
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		return pub, key, err
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		key, err := rsa.GenerateKey(rand.Reader, bits)
		return key.Public(), key, err
	default:
		return nil, nil, errors.New("unknown `alg` for `use` = `sig`")
	}
}

// KeygenEnc generates keypair for corresponding KeyAlgorithm.
func KeygenEnc(alg jose.KeyAlgorithm, bits int) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch alg {
	case jose.RSA1_5, jose.RSA_OAEP, jose.RSA_OAEP_256:
		if bits == 0 {
			bits = 2048
		}
		if bits < 2048 {
			return nil, nil, errors.New("too short key for RSA `alg`, 2048+ is required")
		}
		key, err := rsa.GenerateKey(rand.Reader, bits)
		return key.Public(), key, err
	case jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW:
		var crv elliptic.Curve
		switch bits {
		case 0, 256:
			crv = elliptic.P256()
		case 384:
			crv = elliptic.P384()
		case 521:
			crv = elliptic.P521()
		default:
			return nil, nil, errors.New("unknown elliptic curve bit length, use one of 256, 384, 521")
		}
		key, err := ecdsa.GenerateKey(crv, rand.Reader)
		return key.Public(), key, err
	default:
		return nil, nil, errors.New("unknown `alg` for `use` = `enc`")
	}
}

// GenerateKeys generates enc, sig key
func GenerateKeys(kid string, opt KeyOptions) (jose.JSONWebKey, jose.JSONWebKey, error) {
	var privKey crypto.PublicKey
	var pubKey crypto.PrivateKey
	var err error
	switch opt.Use {
	case "sig":
		pubKey, privKey, err = KeygenSig(jose.SignatureAlgorithm(opt.Alg), opt.Bits)
	case "enc":
		pubKey, privKey, err = KeygenEnc(jose.KeyAlgorithm(opt.Alg), opt.Bits)
	}
	if err != nil {
		return jose.JSONWebKey{}, jose.JSONWebKey{}, errors.New("Unable to generate key: " + err.Error())
	}

	priv := jose.JSONWebKey{Key: privKey, KeyID: kid, Algorithm: opt.Alg, Use: opt.Use}
	pub := jose.JSONWebKey{Key: pubKey, KeyID: kid, Algorithm: opt.Alg, Use: opt.Use}

	if priv.IsPublic() || !pub.IsPublic() || !priv.Valid() || !pub.Valid() {
		return jose.JSONWebKey{}, jose.JSONWebKey{}, errors.New("invalid keys were generated")
	}
	return priv, pub, nil
}
