package keys

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/karantin2020/jwtis"
	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"

	"github.com/karantin2020/svalkey"
	// "github.com/rs/zerolog"
	// "github.com/abronan/valkeyrie"
	"github.com/abronan/valkeyrie/store"
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

var (
	refreshStrategies = []string{
		"refreshBoth",
		"refreshOnExpire",
		"noRefresh",
	}
)

// JWTKeysIssuerSet holds keys info
type JWTKeysIssuerSet struct {
	KID             []byte                 // key id
	Expiry          jwt.NumericDate        // keys expiry time
	AuthTTL         time.Duration          // token expiry duration
	RefreshTTL      time.Duration          // token expiry duration
	RefreshStrategy string                 // optional, values are: 'refreshBoth', 'refreshOnExpire', 'noRefresh' (default)
	Enc             jose.JSONWebKey        // enc private key
	Sig             jose.JSONWebKey        // sig private key
	ContEnc         jose.ContentEncryption // content encryption algorithm
	Locked          bool                   // is this keyset locked for further deletion (lost or other reason)
	SigOpts         jwtis.KeyOptions
	EncOpts         jwtis.KeyOptions
	pubEnc          jose.JSONWebKey // enc public key
	pubSig          jose.JSONWebKey // sig public key
	invalid         bool
	expired         bool
}

// InfoSet holds keys info for list request
type InfoSet struct {
	KID             string `json:"kid"`
	Expiry          int64  `json:"expiry"`
	AuthTTL         int64  `json:"authTTL"`
	RefreshTTL      int64  `json:"refreshTTL"`
	RefreshStrategy string `json:"refreshStrategy"`
	Enc             []byte `json:"enc"`
	Sig             []byte `json:"sig"`
	ContEnc         string `json:"contEnc"`
	Locked          bool   `json:"locked"`
	Valid           bool   `json:"valid"`
	Expired         bool   `json:"expired"`
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
		Sig:    k.pubSig,
		Enc:    k.pubEnc,
		Expiry: k.Expiry,
		Valid:  !k.invalid,
	}
}

// Validate checks Expired() and Valid()
func (k *JWTKeysIssuerSet) Validate() bool {
	return !k.Expired() && k.Valid()
}

func (k *JWTKeysIssuerSet) attachPublic() {
	k.pubEnc = k.Enc.Public()
	k.pubSig = k.Sig.Public()
}

// SigEncKeys represents a structure that holds public or private JWT keys
type SigEncKeys struct {
	Sig             jose.JSONWebKey        `json:"sig"`
	Enc             jose.JSONWebKey        `json:"enc"`
	ContEnc         jose.ContentEncryption `json:"contEnc"`
	Expiry          jwt.NumericDate        `json:"expiry"`
	Valid           bool                   `json:"valid"`
	RefreshStrategy string                 `json:"refresh_strategy"`
}

// DefaultOptions represents default sig ang enc options
type DefaultOptions struct {
	SigAlg          string        // Default algorithm to be used for sign
	SigBits         int           // Default key size in bits for sign
	EncAlg          string        // Default algorithm to be used for encrypt
	EncBits         int           // Default key size in bits for encrypt
	ContEnc         string        // Default content encryption algorithm
	Expiry          time.Duration // Default value for keys ttl
	AuthTTL         time.Duration // Default value for auth jwt ttl
	RefreshTTL      time.Duration // Default value for refresh jwt ttl
	RefreshStrategy string        // optional, values are: 'refreshBoth', 'refreshOnExpire', 'noRefresh' (default)
}

// Repository holds all jose.JSONWebKey's
type Repository struct {
	// Keys map[string]JWTKeysIssuerSet
	DefaultOptions

	defSigOptions jwtis.KeyOptions
	defEncOptions jwtis.KeyOptions

	store  *svalkey.Store
	prefix string

	ml sync.RWMutex
}

// RepoOptions holds options for NewKeysRepo func
type RepoOptions struct {
	Store  *svalkey.Store
	Prefix string
	Opts   *DefaultOptions
}

// New returns pointer to new KeysRepository
func New(repoOpts *RepoOptions) (*Repository, error) {
	if repoOpts == nil {
		return nil, fmt.Errorf("error NewKeysRepo: nil pointer to KeysRepoOptions")
	}
	if repoOpts.Opts == nil {
		return nil, fmt.Errorf("error NewKeysRepo: nil pointer to keysRepo DefaultOptions")
	}
	if repoOpts.Store == nil {
		return nil, fmt.Errorf("error NewKeysRepo: nil pointer to svalkey.Store")
	}
	// remove white spaces if they present in prefix
	repoOpts.Prefix = strings.TrimSpace(repoOpts.Prefix)
	if repoOpts.Prefix == "" {
		return nil, fmt.Errorf("error NewKeysRepo: empty prefix in options")
	}
	p := &Repository{
		store: repoOpts.Store,
	}
	// modPrefix := func(i interface{}) {
	// 	switch i.(type) {
	// 	case *boltdb.BoltDB, *dynamodb.DynamoDB:
	// 		p.prefix = ""
	// 	default:
	// 		p.prefix = repoOpts.Prefix
	// 		if !strings.HasSuffix(p.prefix, "/") {
	// 			p.prefix = p.prefix + "/"
	// 		}
	// 	}
	// }
	// modPrefix(p.store.Store)

	p.prefix = repoOpts.Prefix
	if !strings.HasSuffix(p.prefix, "/") {
		p.prefix = p.prefix + "/"
	}
	p.DefaultOptions = *repoOpts.Opts
	p.DefaultOptions.RefreshStrategy = "refreshOnExpire"
	opts := repoOpts.Opts
	p.defSigOptions = jwtis.KeyOptions{
		Use:  "sig",
		Alg:  opts.SigAlg,
		Bits: opts.SigBits,
	}
	p.defEncOptions = jwtis.KeyOptions{
		Use:  "enc",
		Alg:  opts.EncAlg,
		Bits: opts.EncBits,
	}
	return p, nil
}

// NewKey creates new key with key_id and adds it to repository
// returns public jose.JSONWebKey
func (p *Repository) NewKey(kid string, opts *DefaultOptions) (*SigEncKeys, error) {
	if p == nil {
		return nil,
			fmt.Errorf("error in NewKey: pointer to KeysRepository is nil")
	}
	if opts == nil {
		return nil,
			fmt.Errorf("error in NewKey: pointer to key options is nil")
	}
	// Keys in db must be checked for strong consistency
	exists, privKeys, err := p.KeyExists([]byte(kid))
	if err != nil {
		return nil,
			fmt.Errorf("error in NewKey checking key existence: %s", err.Error())
	}
	if exists {
		if !privKeys.Valid() {
			return nil, ErrKeysExistInvalid
		}
		if !privKeys.Expired() {
			return nil, ErrKeysExist
		}
		return nil, ErrKeysExpired
	}

	if opts.RefreshStrategy != "" {
		if !stringInSlice(opts.RefreshStrategy, refreshStrategies) {
			return nil, fmt.Errorf("NewKey error: invalid RefreshStrategy option value")
		}
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
	privKeys.Sig, _, err = jwtis.GenerateKeys(kid, privKeys.SigOpts)
	if err != nil {
		return nil, fmt.Errorf("error generating sig keys: %s", err.Error())
	}
	privKeys.Enc, _, err = jwtis.GenerateKeys(kid, privKeys.EncOpts)
	if err != nil {
		return nil, fmt.Errorf("error generating enc keys: %s", err.Error())
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
	} else {
		privKeys.RefreshStrategy = p.DefaultOptions.RefreshStrategy
	}
	if opts.ContEnc != "" {
		privKeys.ContEnc = jose.ContentEncryption(opts.ContEnc)
	} else {
		privKeys.ContEnc = jose.ContentEncryption(p.DefaultOptions.ContEnc)
	}
	return p.AddKey(privKeys)
}

// KeyExists return true is key with kid is in boltDB
func (p *Repository) KeyExists(kid []byte) (bool, *JWTKeysIssuerSet, error) {
	nKid := p.normalizeKid(string(kid))
	privKeys := JWTKeysIssuerSet{}
	exists := false
	p.ml.RLock()
	defer p.ml.RUnlock()
	exists, err := p.store.Exists(nKid, &store.ReadOptions{
		Consistent: true,
	})
	if err != nil {
		if err == store.ErrKeyNotFound {
			return false, &privKeys, nil
		}
		return exists, nil, fmt.Errorf("error looking for key %s: %s", string(kid), err.Error())
	}
	if exists {
		err = p.store.Get(nKid, &privKeys, &store.ReadOptions{
			Consistent: true,
		})
		if err != nil {
			return exists, nil, fmt.Errorf("error loading key %s: %s", string(kid), err.Error())
		}
	}
	return exists, &privKeys, nil
}

// AddKey adds jose.JSONWebKey with key.KeyID to repository
// returns public jose.JSONWebKey
func (p *Repository) AddKey(key *JWTKeysIssuerSet) (*SigEncKeys, error) {
	nKid := p.normalizeKid(string(key.KID))
	exists, privKeys, err := p.KeyExists(key.KID)
	if err != nil {
		return nil,
			fmt.Errorf("error in AddKey checking key existence: %s", err.Error())
	}
	if exists {
		if !privKeys.Expired() {
			return nil,
				fmt.Errorf("error adding new keys: keys with kid %s exist and not expired", key.KID)
		}
		return nil, ErrKeysExpired
	}
	if !key.Valid() {
		return nil,
			fmt.Errorf("error adding new keys: new keys with kid %s are not valid", key.KID)
	}
	if key.Expired() {
		return nil,
			fmt.Errorf("error adding new keys: new key with kid %s is expired", key.KID)
	}
	key.attachPublic()
	p.ml.Lock()
	defer p.ml.Unlock()
	err = p.store.Put(nKid, key, nil)
	if err != nil {
		return nil, fmt.Errorf("error save keys for %s in repository: %s", string(key.KID), err.Error())
	}
	pubKeys := SigEncKeys{
		Enc:             key.pubEnc,
		Sig:             key.pubSig,
		ContEnc:         key.ContEnc,
		Expiry:          key.Expiry,
		Valid:           !key.invalid,
		RefreshStrategy: key.RefreshStrategy,
	}
	return &pubKeys, nil
}

// DelKey deletes key from cache and boltDB
func (p *Repository) DelKey(kid string) error {
	nKid := p.normalizeKid(kid)
	p.ml.Lock()
	defer p.ml.Unlock()
	exists, err := p.store.Exists(nKid, &store.ReadOptions{
		Consistent: true,
	})
	if err != nil {
		return fmt.Errorf("error delete: error looking for key %s: %s", kid, err.Error())
	}
	if !exists {
		return jwtis.ErrKeyNotFound
	}

	err = p.store.Delete(nKid)
	if err != nil {
		return fmt.Errorf("error delete key %s: %s", kid, err.Error())
	}
	return nil
}

// GetPublicKeys returns from boltDB public keys with kid
// returns pointer to public jose.JSONWebKey
func (p *Repository) GetPublicKeys(kid string) (*SigEncKeys, error) {
	p.ml.RLock()
	defer p.ml.RUnlock()
	privKeys, err := p.GetPrivateKeys(kid)
	if err != nil {
		return nil, err
	}
	pubKeys := SigEncKeys{
		Enc:             privKeys.Enc.Public(),
		Sig:             privKeys.Sig.Public(),
		ContEnc:         privKeys.ContEnc,
		Expiry:          privKeys.Expiry,
		Valid:           privKeys.Valid,
		RefreshStrategy: privKeys.RefreshStrategy,
	}
	return &pubKeys, nil
}

// GetPrivateKeys returns from boltDB private keys with kid
// returns pointer to public jose.JSONWebKey
func (p *Repository) GetPrivateKeys(kid string) (SigEncKeys, error) {
	p.ml.RLock()
	defer p.ml.RUnlock()
	exists, privKeys, err := p.KeyExists([]byte(kid))
	if err != nil {
		return SigEncKeys{},
			fmt.Errorf("error check keys existence: %s", err.Error())
	}
	if !exists {
		return SigEncKeys{}, ErrKeysNotFound
	}
	if privKeys.Expired() {
		return SigEncKeys{}, ErrKeysExpired
	}
	if !privKeys.Valid() {
		return SigEncKeys{}, ErrKeysInvalid
	}
	retKeys := SigEncKeys{
		Enc:             privKeys.Enc,
		Sig:             privKeys.Sig,
		ContEnc:         privKeys.ContEnc,
		Expiry:          privKeys.Expiry,
		Valid:           !privKeys.invalid,
		RefreshStrategy: privKeys.RefreshStrategy,
	}
	return retKeys, nil
}

// ListKeys returns info about keys for all registered kids
func (p *Repository) ListKeys() ([]InfoSet, error) {
	var resErr jwtis.Error
	keysList := []InfoSet{}
	p.ml.RLock()
	defer p.ml.RUnlock()
	kvs, err := p.loadKeys()
	if err != nil {
		resErr.Append(fmt.Errorf("error loading keys list: %s", err.Error()))
	}
	for i := range kvs {
		keySet := InfoSet{
			KID:             string(kvs[i].KID),
			Expiry:          int64(kvs[i].Expiry),
			AuthTTL:         int64(kvs[i].AuthTTL),
			RefreshTTL:      int64(kvs[i].RefreshTTL),
			RefreshStrategy: kvs[i].RefreshStrategy,
			Locked:          kvs[i].Locked,
		}
		keySet.Valid = kvs[i].Valid()
		keySet.Expired = kvs[i].Expired()
		b, err := json.Marshal(kvs[i].Enc.Public())
		if err != nil {
			resErr.Append(fmt.Errorf("error marshal public enc key for kid: '%s': %s", string(kvs[i].KID), err.Error()))
		}
		keySet.Enc = b
		b, err = json.Marshal(kvs[i].Sig.Public())
		if err != nil {
			resErr.Append(fmt.Errorf("error marshal public sig key for kid: '%s': %s", string(kvs[i].KID), err.Error()))
		}
		keySet.Sig = b
		keySet.ContEnc = string(kvs[i].ContEnc)
		keysList = append(keysList, keySet)
	}
	if len(resErr) > 0 {
		return keysList, resErr
	}
	return keysList, nil
}

func (p *Repository) normalizeKid(kid string) string {
	return p.prefix + kid
}

func (p *Repository) loadKeys() ([]JWTKeysIssuerSet, error) {
	keysList := []JWTKeysIssuerSet{}
	_, err := p.store.List(p.prefix, &keysList, &store.ReadOptions{
		Consistent: true,
	})
	if err != nil {
		return nil, err
	}
	for i := range keysList {
		keysList[i].Validate()
		keysList[i].attachPublic()
	}
	return keysList, nil
}

func stringInSlice(a string, list []string) bool {
	for i := range list {
		if list[i] == a {
			return true
		}
	}
	return false
}
