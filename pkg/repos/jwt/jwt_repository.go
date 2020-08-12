package jwt

import (
	"fmt"
	"strings"
	"sync"

	"github.com/karantin2020/jwtis"
	"github.com/pkg/errors"
	jwt "gopkg.in/square/go-jose.v2/jwt"

	"github.com/abronan/valkeyrie/store"
	"github.com/karantin2020/svalkey"
)

var (
	// ErrJWTNotFound describes error when kid is missing in repository
	ErrJWTNotFound = errors.New("jwt not found in repository")
	// ErrJWTExpired fires when jwt exist and expired
	ErrJWTExpired = errors.New("jwt exists in repository, marked as expired, must be deleted")
	// ErrJWTInvalid fires when jwt are not valid
	ErrJWTInvalid = errors.New("jwt exists in repository and is not valid")
)

// StoreValue holds internal storage structure
type StoreValue struct {
	JTI          string
	RefreshToken string
	Expiry       jwt.NumericDate // RefreshToken expiry time
}

// DefaultOptions for repo
type DefaultOptions struct {
}

// Repository holds all jwt
type Repository struct {
	store  *svalkey.Store
	prefix string

	ml sync.RWMutex
}

// RepoOptions holds options for NewJWTRepo func
type RepoOptions struct {
	Store  *svalkey.Store
	Prefix string
	Opts   *DefaultOptions
}

// New returns pointer to new KeysRepository
func New(repoOpts *RepoOptions) (*Repository, error) {
	if repoOpts == nil {
		return nil, fmt.Errorf("jwt repo: nil pointer to JWTRepoOptions")
	}
	if repoOpts.Store == nil {
		return nil, fmt.Errorf("jwt repo: nil pointer to svalkey.Store")
	}
	// remove white spaces if they present in prefix
	repoOpts.Prefix = strings.TrimSpace(repoOpts.Prefix)
	if repoOpts.Prefix == "" {
		return nil, fmt.Errorf("jwt repo: empty prefix in options")
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
	return p, nil
}

// JWTExists return true if jwt is in db
func (p *Repository) JWTExists(jti string) (bool, error) {
	nJti := p.normalizeKid(jti)
	exists := false
	p.ml.RLock()
	defer p.ml.RUnlock()
	exists, err := p.store.Exists(nJti, &store.ReadOptions{
		Consistent: true,
	})
	if err != nil {
		if err == store.ErrKeyNotFound {
			return false, nil
		}
		return exists, fmt.Errorf("jwt repo: error looking for jwt %s in db: %s", jti, err.Error())
	}
	// value := StoreValue{}
	// if exists {
	// 	err = p.store.Get(nJti, &value, &store.ReadOptions{
	// 		Consistent: true,
	// 	})
	// 	if err != nil {
	// 		return exists, fmt.Errorf("jwt repo: error loading jwt %s: %s", string(nJti), err.Error())
	// 	}
	// 	if value.RefreshToken == "" {
	// 		return exists, fmt.Errorf("jwt repo: invalid jwt %s: refresh token is empty", string(nJti))
	// 	}
	// 	if !value.Expiry.Time().After(time.Now()) {
	// 		return exists, fmt.Errorf("jwt repo: invalid jwt %s: refresh token is expired", string(nJti))
	// 	}
	// }
	return exists, nil
}

// Store stores jwt in db
func (p *Repository) Store(val *StoreValue) error {
	nJti := p.normalizeKid(string(val.JTI))
	exists, err := p.JWTExists(val.JTI)
	if err != nil {
		return fmt.Errorf("jwt repo: error store token: %s", err.Error())
	}
	if exists {
		return fmt.Errorf("jwt repo: error store token: jti %s exists and not expired", val.JTI)
	}
	p.ml.Lock()
	defer p.ml.Unlock()
	err = p.store.Put(nJti, val, nil)
	if err != nil {
		return fmt.Errorf("jwt repo: error store token for %s in repository: %s", string(val.JTI), err.Error())
	}
	return nil
}

// Del deletes jwt from db
func (p *Repository) Del(jti string) error {
	nJti := p.normalizeKid(jti)
	p.ml.Lock()
	defer p.ml.Unlock()
	exists, err := p.JWTExists(nJti)
	if err != nil {
		return fmt.Errorf("jwt repo: delete, error looking for key %s: %s", jti, err.Error())
	}
	if !exists {
		return jwtis.ErrKeyNotFound
	}
	err = p.store.Delete(nJti)
	if err != nil {
		return fmt.Errorf("jwt repo: error delete key %s: %s", jti, err.Error())
	}
	return nil
}

// List returns all jwt in db
// it's dangerous operation because db may hold to much tokens
func (p *Repository) List() ([]StoreValue, error) {
	p.ml.RLock()
	defer p.ml.RUnlock()
	toks, err := p.loadJWT()
	if err != nil {
		return nil, fmt.Errorf("jwt repo: error loading jwt list: %s", err.Error())
	}
	return toks, nil
}

func (p *Repository) normalizeKid(kid string) string {
	return p.prefix + kid
}

func (p *Repository) loadJWT() ([]StoreValue, error) {
	tokList := []StoreValue{}
	_, err := p.store.List(p.prefix, &tokList, &store.ReadOptions{
		Consistent: true,
	})
	if err != nil {
		return nil, err
	}
	return tokList, nil
}

func stringInSlice(a string, list []string) bool {
	for i := range list {
		if list[i] == a {
			return true
		}
	}
	return false
}
