package jwtis

import (
	"encoding/json"
	"fmt"
	"sync"
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
	ErrKeysExpired = errors.New("keys with kid exist in repository, marked as expired, must be deleted")
	// ErrKeysExist if keys exist and are valid
	ErrKeysExist = errors.New("keys with kid exist in repository and are valid")
	// ErrKeysExistInvalid if keys exist and are not valid
	ErrKeysExistInvalid = errors.New("keys with kid exist in repository and are not valid")
	// ErrKeysInvalid fires when keys are not valid
	ErrKeysInvalid = errors.New("keys with kid exist in repository and are not valid")
)

// JWTKeysIssuerSet holds keys info
type JWTKeysIssuerSet struct {
	KID             []byte          // key id
	Expiry          jwt.NumericDate // keys expiry time
	AuthTTL         time.Duration   // token expiry duration
	RefreshTTL      time.Duration   // token expiry duration
	RefreshStrategy string          // optional, values are: 'refreshBoth', 'refreshOnExpire', 'noRefresh' (default)
	Enc             jose.JSONWebKey // enc private key
	Sig             jose.JSONWebKey // sig private key
	Locked          bool            // is this keyset locked for further deletion (lost or other reason)
	SigOpts         KeyOptions
	EncOpts         KeyOptions
	pubEnc          jose.JSONWebKey // enc public key
	pubSig          jose.JSONWebKey // sig public key
	invalid         bool
	expired         bool
}

// KeysInfoSet holds keys info for list request
type KeysInfoSet struct {
	KID             string
	Expiry          int64
	AuthTTL         int64
	RefreshTTL      int64
	RefreshStrategy string
	Enc             []byte
	Sig             []byte
	Locked          bool
	Valid           bool
	Expired         bool
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
	if len(k.KID) == 0 {
		k.invalid = true
		return false
	}
	return true
}

// Public returns SigEncKeys with public sig and enc keys
func (k *JWTKeysIssuerSet) Public() SigEncKeys {
	return SigEncKeys{
		Sig:    &k.pubSig,
		Enc:    &k.pubEnc,
		Expiry: k.Expiry,
		Valid:  !k.invalid,
	}
}

func (k *JWTKeysIssuerSet) attachPublic() {
	k.pubEnc = k.Enc.Public()
	k.pubSig = k.Sig.Public()
}

// SigEncKeys represents a structure that holds public or private JWT keys
type SigEncKeys struct {
	Sig             *jose.JSONWebKey `json:"sig"`
	Enc             *jose.JSONWebKey `json:"enc"`
	Expiry          jwt.NumericDate  `json:"expiry"`
	Valid           bool             `json:"valid"`
	RefreshStrategy string           `json:"refresh_strategy"`
}

// KeyOptions represent the set of option to create sig or enc keys
type KeyOptions struct {
	Use, Alg string
	Bits     int
}

// DefaultOptions represents default sig ang enc options
type DefaultOptions struct {
	SigAlg          string        // Default algorithn to be used for sign
	SigBits         int           // Default key size in bits for sign
	EncAlg          string        // Default algorithn to be used for encrypt
	EncBits         int           // Default key size in bits for encrypt
	Expiry          time.Duration // Default value for keys ttl
	AuthTTL         time.Duration // Default value for auth jwt ttl
	RefreshTTL      time.Duration // Default value for refresh jwt ttl
	RefreshStrategy string        // optional, values are: 'refreshBoth', 'refreshOnExpire', 'noRefresh' (default)
}

// KeysRepository holds all jose.JSONWebKey's
type KeysRepository struct {
	Keys map[string]JWTKeysIssuerSet
	DefaultOptions

	defSigOptions KeyOptions
	defEncOptions KeyOptions

	boltDB     *bolt.DB
	bucketName []byte // repository bucket name in boltDB
	encKey     *Key
	nonce      []byte
	ml         sync.RWMutex
}

// Init initiates created KeysRepository
func (p *KeysRepository) Init(db *bolt.DB, bucketName []byte,
	opts *DefaultOptions, encKey *Key, nonce []byte) error {
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
	p.DefaultOptions.RefreshStrategy = "noRefresh"
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
	p.encKey = encKey
	p.nonce = nonce
	err := p.LoadAll()
	if err != nil {
		return fmt.Errorf("error initianing keys repository: %s", err.Error())
	}
	return nil
}

// CheckKeys checks if all keys are valid and are not expired
func (p *KeysRepository) CheckKeys() error {
	var res Error
	p.ml.RLock()
	defer p.ml.RUnlock()
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
// returns public jose.JSONWebKey
func (p *KeysRepository) NewKey(kid string, opts *DefaultOptions) (SigEncKeys, error) {
	fmt.Printf("keyrepo: newkey for kid '%s'\n", kid)
	if p == nil {
		return SigEncKeys{},
			fmt.Errorf("error in NewKey: pointer to KeysRepository is nil")
	}
	if opts == nil {
		return SigEncKeys{},
			fmt.Errorf("error in NewKey: pointer to key options is nil")
	}
	// Keys in db must be checked for strong consistency
	exists, privKeys, err := p.KeyExists([]byte(kid))
	if err != nil {
		return SigEncKeys{},
			fmt.Errorf("error in NewKey checking key existance: %s", err.Error())
	}
	if exists {
		if !privKeys.Valid() {
			return SigEncKeys{}, ErrKeysExistInvalid
		}
		if !privKeys.Expired() {
			return SigEncKeys{}, ErrKeysExist
		}
		return SigEncKeys{}, ErrKeysExpired
	}

	// If there is no key with kid in db, we continue creation of new key
	privKeys.KID = []byte(kid)
	privKeys.Locked = false

	privKeys.SigOpts = p.defSigOptions
	privKeys.EncOpts = p.defEncOptions
	now := time.Now()
	if opts.SigAlg != "" {
		privKeys.SigOpts.Alg = opts.SigAlg
	}
	if opts.SigBits != 0 {
		privKeys.SigOpts.Bits = opts.SigBits
	}
	if opts.EncAlg != "" {
		privKeys.EncOpts.Alg = opts.EncAlg
	}
	if opts.EncBits != 0 {
		privKeys.EncOpts.Bits = opts.EncBits
	}
	if int64(opts.Expiry) != 0 {
		privKeys.Expiry = jwt.NumericDate(now.Add(opts.Expiry).Unix())
	} else {
		privKeys.Expiry = jwt.NumericDate(now.Add(p.DefaultOptions.Expiry).Unix())
	}
	privKeys.Sig, _, err = GenerateKeys(kid, privKeys.SigOpts)
	if err != nil {
		return SigEncKeys{}, fmt.Errorf("error generating sig keys: %s", err.Error())
	}
	privKeys.Enc, _, err = GenerateKeys(kid, privKeys.EncOpts)
	if err != nil {
		return SigEncKeys{}, fmt.Errorf("error generating enc keys: %s", err.Error())
	}
	if int64(opts.AuthTTL) != 0 {
		privKeys.AuthTTL = opts.AuthTTL
	} else {
		privKeys.AuthTTL = p.DefaultOptions.AuthTTL
	}
	if int64(opts.RefreshTTL) != 0 {
		privKeys.RefreshTTL = opts.RefreshTTL
	} else {
		privKeys.RefreshTTL = p.DefaultOptions.RefreshTTL
	}
	if opts.RefreshStrategy != "" {
		privKeys.RefreshStrategy = opts.RefreshStrategy
	}
	return p.AddKey(privKeys)
}

// KeyExists return true is key with kid is in boltDB
func (p *KeysRepository) KeyExists(kid []byte) (bool, *JWTKeysIssuerSet, error) {
	privKeys := JWTKeysIssuerSet{}
	exists := false
	p.ml.RLock()
	defer p.ml.RUnlock()
	if err := p.boltDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(p.bucketName)
		if err := LoadSealed(p.encKey, p.nonce, b, kid, &privKeys); err != nil {
			if err == ErrKeyNotFound {
				return nil
			}
			return fmt.Errorf("error loading key %s: %s", string(kid), err.Error())
		}
		exists = true
		return nil
	}); err != nil {
		return exists, nil, fmt.Errorf("error looking for key %s: %s", string(kid), err.Error())
	}
	return exists, &privKeys, nil
}

// AddKey adds jose.JSONWebKey with key.KeyID to repository
// returns public jose.JSONWebKey
func (p *KeysRepository) AddKey(key *JWTKeysIssuerSet) (SigEncKeys, error) {
	exists, privKeys, err := p.KeyExists(key.KID)
	if err != nil {
		return SigEncKeys{},
			fmt.Errorf("error in AddKey checking key existance: %s", err.Error())
	}
	if exists {
		if !privKeys.Expired() {
			return SigEncKeys{},
				fmt.Errorf("error adding new keys: keys with kid %s exist and not expired", key.KID)
		}
		return SigEncKeys{}, ErrKeysExpired
	}
	if !key.Valid() {
		return SigEncKeys{},
			fmt.Errorf("error adding new keys: new keys with kid %s are not valid", key.KID)
	}
	if key.Expired() {
		return SigEncKeys{},
			fmt.Errorf("error adding new keys: new key with kid %s is expired", key.KID)
	}
	key.attachPublic()
	p.ml.Lock()
	defer p.ml.Unlock()
	if err := p.boltDB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(p.bucketName)
		if err := SaveSealed(p.encKey, p.nonce, b, key.KID, key); err != nil {
			return fmt.Errorf("error saving keys with kid %s", string(key.KID))
		}
		return nil
	}); err != nil {
		return SigEncKeys{}, fmt.Errorf("error save keys in repository: %s", err.Error())
	}
	p.Keys[string(key.KID)] = *key
	pubKeys := SigEncKeys{
		Enc:             &key.pubEnc,
		Sig:             &key.pubSig,
		Expiry:          key.Expiry,
		Valid:           !key.invalid,
		RefreshStrategy: key.RefreshStrategy,
	}
	return pubKeys, nil
}

// DelKey deletes key from cache and boltDB
func (p *KeysRepository) DelKey(kid string) error {
	p.ml.Lock()
	defer p.ml.Unlock()
	if err := p.boltDB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(p.bucketName)

		val := b.Get([]byte(kid))
		if val == nil {
			return ErrKeyNotFound
		}

		if err := b.Delete([]byte(kid)); err != nil {
			return fmt.Errorf("error delete key with kid %s: %s", kid, err.Error())
		}
		return nil
	}); err != nil {
		if err == ErrKeyNotFound {
			return err
		}
		return fmt.Errorf("error delete keys from repository: %s", err.Error())
	}
	delete(p.Keys, kid)
	return nil
}

// GetPublicKeys returns from boltDB public keys with kid
// returns pointer to public jose.JSONWebKey
func (p *KeysRepository) GetPublicKeys(kid string) (SigEncKeys, error) {
	p.ml.RLock()
	key, ok := p.Keys[kid]
	p.ml.RUnlock()
	if !ok {
		return SigEncKeys{}, ErrKeysNotFound
	}
	if key.Expired() {
		return SigEncKeys{}, ErrKeysExpired
	}
	if !key.Valid() {
		return SigEncKeys{}, ErrKeysInvalid
	}
	pubKeys := SigEncKeys{
		Enc:             &key.pubEnc,
		Sig:             &key.pubSig,
		Expiry:          key.Expiry,
		Valid:           !key.invalid,
		RefreshStrategy: key.RefreshStrategy,
	}
	return pubKeys, nil
}

// GetPrivateKeys returns from boltDB private keys with kid
// returns pointer to public jose.JSONWebKey
func (p *KeysRepository) GetPrivateKeys(kid string) (SigEncKeys, error) {
	p.ml.RLock()
	key, ok := p.Keys[kid]
	p.ml.RUnlock()
	if !ok {
		return SigEncKeys{}, ErrKeysNotFound
	}
	if key.Expired() {
		return SigEncKeys{}, ErrKeysExpired
	}
	privKeys := SigEncKeys{
		Enc:             &key.Enc,
		Sig:             &key.Sig,
		Expiry:          key.Expiry,
		Valid:           !key.invalid,
		RefreshStrategy: key.RefreshStrategy,
	}
	return privKeys, nil
}

// ListKeys returns info about keys for all registered kids
func (p *KeysRepository) ListKeys() ([]KeysInfoSet, error) {
	var resErr Error
	keysList := make([]KeysInfoSet, 0, len(p.Keys))
	p.LoadAll()
	p.ml.RLock()
	defer p.ml.RUnlock()
	for k, v := range p.Keys {
		keySet := KeysInfoSet{
			KID:             k,
			Expiry:          int64(v.Expiry),
			AuthTTL:         int64(v.AuthTTL),
			RefreshTTL:      int64(v.RefreshTTL),
			RefreshStrategy: v.RefreshStrategy,
			Locked:          v.Locked,
		}
		keySet.Valid = v.Valid()
		keySet.Expired = v.Expired()
		b, err := json.Marshal(v.Enc.Public())
		if err != nil {
			resErr.Append(fmt.Errorf("error marshal public enc key for kid: '%s': %s", k, err.Error()))
		}
		keySet.Enc = b
		b, err = json.Marshal(v.Sig.Public())
		if err != nil {
			resErr.Append(fmt.Errorf("error marshal public sig key for kid: '%s': %s", k, err.Error()))
		}
		keySet.Sig = b
		keysList = append(keysList, keySet)
	}
	if len(resErr) > 0 {
		return keysList, resErr
	}
	return keysList, nil
}

// SaveAll puts all keys from memory to boltDB
func (p *KeysRepository) SaveAll() error {
	p.ml.Lock()
	defer p.ml.Unlock()
	if err := p.boltDB.Batch(func(tx *bolt.Tx) error {
		b := tx.Bucket(p.bucketName)
		for _, v := range p.Keys {
			if err := SaveSealed(p.encKey, p.nonce, b, v.KID, v); err != nil {
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
	p.ml.Lock()
	defer p.ml.Unlock()
	if err := p.boltDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(p.bucketName)
		err := b.ForEach(func(k, v []byte) error {
			if v == nil {
				return fmt.Errorf("error loading key %s, value is empty", string(k))
			}

			buf := make([]byte, 0, len(v))
			value, err := p.encKey.Open(buf, p.nonce, v, nil)
			if err != nil {
				return err
			}
			res := JWTKeysIssuerSet{}
			if err := json.Unmarshal(value, &res); err != nil {
				return fmt.Errorf("in loading key %s failed to unmarshal: %s", string(k), err.Error())
			}
			res.Valid()
			res.Expired()
			res.attachPublic()
			p.Keys[string(res.KID)] = res
			return nil
		})
		return err
	}); err != nil {
		return fmt.Errorf("error LoadAll keys repository: %s", err.Error())
	}
	return nil
}
