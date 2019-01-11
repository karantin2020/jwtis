package jwtis

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "github.com/coreos/bbolt"
	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

var (
	// ErrKeysNotFound describes error when kid is missing in repository
	ErrKeysNotFound = errors.New("keys with kid not found in repository")
	// ErrKeysExpired fires when keys exist and expired
	ErrKeysExpired = errors.New("keys with kid exist in repository, marks as expired, must be deleted")
	// ErrKeysInvalid fires when keys are not valid
	ErrKeysInvalid = errors.New("keys with kid exist in repository and are not valid")
)

// JWTKeysIssuerSet holds jwt info
type JWTKeysIssuerSet struct {
	KID     []byte          // key id
	Expiry  jwt.NumericDate // keys expiry time
	Enc     jose.JSONWebKey // enc private key
	Sig     jose.JSONWebKey // sig private key
	Locked  bool            // is this keyset locked for further deletion (lost or other reason)
	invalid bool
	expired bool
}

// Expired returns true if JWTKeysIssuerSet is expired
func (k *JWTKeysIssuerSet) Expired() bool {
	now := time.Now()
	if now.After(k.Expiry.Time()) {
		k.expired = true
		return true
	}
	return false
}

// Valid checks keys for validity
func (k *JWTKeysIssuerSet) Valid() bool {
	if k.Enc.IsPublic() || k.Sig.IsPublic() || !k.Enc.Valid() || !k.Sig.Valid() {
		k.invalid = true
		return false
	}
	return true
}

// SigEncKeys represents a structure that holds public or private JWT keys
type SigEncKeys struct {
	Sig    jose.JSONWebKey
	Enc    jose.JSONWebKey
	Expiry jwt.NumericDate
}

// KeyOptions represent the set of option to create sig or enc keys
type KeyOptions struct {
	Use, Alg string
	Bits     int
}

// DefaultOptions represents default sig ang enc options
type DefaultOptions struct {
	SigAlg  string // Default algorithn to be used for sign
	SigBits int    // Default key size in bits for sign
	EncAlg  string // Default algorithn to be used for encrypt
	EncBits int    // Default key size in bits for encrypt
	Expiry  time.Duration
}

// KeysRepository holds all jose.JSONWebKey's
type KeysRepository struct {
	Keys map[string]JWTKeysIssuerSet
	DefaultOptions

	defSigOptions KeyOptions
	defEncOptions KeyOptions

	boltDB     *bolt.DB
	bucketName []byte // repository bucket name in boltDB
}

// Init initiates created KeysRepository
func (p *KeysRepository) Init(db *bolt.DB, bucketName []byte, opts *DefaultOptions) {
	if p == nil {
		panic("KeysRepository pointer is nil")
	}
	if opts == nil {
		panic("options pointer in key repository init is nil")
	}
	p.boltDB = db
	p.bucketName = bucketName
	p.Keys = make(map[string]JWTKeysIssuerSet)
	p.DefaultOptions = *opts
	p.defSigOptions = KeyOptions{
		Use:  "sig",
		Alg:  opts.SigAlg,
		Bits: opts.SigBits,
	}
	p.defEncOptions = KeyOptions{
		Use:  "enc",
		Alg:  opts.EncAlg,
		Bits: opts.EncBits,
	}
}

// CheckKeys checks if all keys are valid and are not expired
func (p *KeysRepository) CheckKeys() error {
	var res Error
	for k, v := range p.Keys {
		if v.invalid || !v.Valid() {
			res.Append(fmt.Errorf("keys with kid %s are invalid", k))
		}
		if v.expired || v.Expired() {
			res.Append(fmt.Errorf("keys with kid %s are expired", k))
		}
	}
	return res
}

// NewKey creates new key with key_id and adds it to repository
// returns pointer to public jose.JSONWebKey
func (p *KeysRepository) NewKey(kid string, opts *DefaultOptions) (SigEncKeys, error) {
	privKeys := JWTKeysIssuerSet{}
	exists := false
	// Keys in db must be checked for strong consistency
	if err := p.boltDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(p.bucketName)
		if err := load(b, []byte(kid), &privKeys); err != nil {
			if err == ErrKeyNotFound {
				return nil
			}
			return fmt.Errorf("error loading key %s: %s", []byte(kid), err.Error())
		}
		exists = true
		return nil
	}); err != nil {
		return SigEncKeys{}, fmt.Errorf("error looking for key %s: %s", []byte(kid), err.Error())
	}

	if exists {
		if !privKeys.Expired() {
			return SigEncKeys{},
				fmt.Errorf("error creating new keys: keys with kid %s exist and not expired", string(kid))
		}
		return SigEncKeys{}, ErrKeysExpired
	}

	// If there is no key with kid in db, we continue creation of new key
	privKeys.KID = []byte(kid)
	privKeys.Locked = false

	pubKeys := SigEncKeys{}
	s := p.defSigOptions
	e := p.defEncOptions
	now := time.Now()
	if opts != nil {
		s.Alg = opts.SigAlg
		s.Bits = opts.SigBits
		e.Alg = opts.EncAlg
		e.Bits = opts.EncBits
		privKeys.Expiry = jwt.NewNumericDate(now.Add(opts.Expiry))
	} else {
		privKeys.Expiry = jwt.NewNumericDate(now.Add(p.DefaultOptions.Expiry))
	}
	pubKeys.Expiry = privKeys.Expiry
	var err error
	privKeys.Sig, pubKeys.Sig, err = GenerateKeys(kid, s)
	if err != nil {
		return SigEncKeys{}, fmt.Errorf("error generating sig keys: %s", err.Error())
	}
	privKeys.Enc, pubKeys.Enc, err = GenerateKeys(kid, e)
	if err != nil {
		return SigEncKeys{}, fmt.Errorf("error generating enc keys: %s", err.Error())
	}
	return p.AddKey(&privKeys)
}

// AddKey adds jose.JSONWebKey with key.KeyID to repository
// returns pointer to public jose.JSONWebKey
func (p *KeysRepository) AddKey(key *JWTKeysIssuerSet) (SigEncKeys, error) {
	if err := p.boltDB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(p.bucketName)
		if err := save(b, key.KID, key); err != nil {
			return fmt.Errorf("error saving keys with kid %s", string(key.KID))
		}
		return nil
	}); err != nil {
		return SigEncKeys{}, fmt.Errorf("error save keys in repository: %s", err.Error())
	}
	p.Keys[string(key.KID)] = *key
	pubKeys := SigEncKeys{
		Enc:    key.Enc.Public(),
		Sig:    key.Sig.Public(),
		Expiry: key.Expiry,
	}
	return pubKeys, nil
}

// GetPublicKeys returns from boltDB public keys with kid
// returns pointer to public jose.JSONWebKey
func (p *KeysRepository) GetPublicKeys(kid string) (SigEncKeys, error) {
	key, ok := p.Keys[kid]
	if !ok {
		return SigEncKeys{}, ErrKeysNotFound
	}
	if key.Expired() {
		return SigEncKeys{}, fmt.Errorf("error get public keys for kid %s: %s", kid, ErrKeysExpired.Error())
	}
	pubKeys := SigEncKeys{
		Enc:    key.Enc.Public(),
		Sig:    key.Sig.Public(),
		Expiry: key.Expiry,
	}
	return pubKeys, nil
}

// GetPrivateKeys returns from boltDB private keys with kid
// returns pointer to public jose.JSONWebKey
func (p *KeysRepository) GetPrivateKeys(kid string) (SigEncKeys, error) {
	key, ok := p.Keys[kid]
	if !ok {
		return SigEncKeys{}, ErrKeysNotFound
	}
	if key.Expired() {
		return SigEncKeys{}, fmt.Errorf("error get private keys for kid %s: %s", kid, ErrKeysExpired.Error())
	}
	privKeys := SigEncKeys{
		Enc:    key.Enc,
		Sig:    key.Sig,
		Expiry: key.Expiry,
	}
	return privKeys, nil
}

// SaveAll puts all keys from memory to boltDB
func (p *KeysRepository) SaveAll() error {
	if err := p.boltDB.Batch(func(tx *bolt.Tx) error {
		b := tx.Bucket(p.bucketName)
		for _, v := range p.Keys {
			if err := save(b, v.KID, v); err != nil {
				return fmt.Errorf("error saving keys with kid %s", string(v.KID))
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("error SaveAll keys repository: %s", err.Error())
	}
	return nil
}

// LoadAll loads all keys from boltDB to memory
func (p *KeysRepository) LoadAll() error {
	if err := p.boltDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(p.bucketName)
		err := b.ForEach(func(k, v []byte) error {
			if v == nil {
				return fmt.Errorf("error loading key %s, value is empty", string(k))
			}
			res := JWTKeysIssuerSet{}
			if err := json.Unmarshal(v, &res); err != nil {
				return fmt.Errorf("in loading key %s failed to unmarshal: %s", string(k), err.Error())
			}
			res.Valid()
			res.Expired()
			p.Keys[string(res.KID)] = res
			return nil
		})
		return err
	}); err != nil {
		return fmt.Errorf("error LoadAll keys repository: %s", err.Error())
	}
	return nil
}
