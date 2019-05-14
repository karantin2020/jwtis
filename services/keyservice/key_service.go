package keyservice

import (
	"fmt"
	"time"

	"github.com/karantin2020/jwtis"
	"github.com/rs/zerolog"
)

var (
	// ErrKIDExists if kid exist when register new key set
	ErrKIDExists = fmt.Errorf("cann't register new keys: kid exists")
	log          zerolog.Logger
)

// KeyService implements server-side key service logic
type KeyService struct {
	keysRepo *jwtis.KeysRepository
}

// New returns pointer to new KeyService instance and error
func New(keysrepo *jwtis.KeysRepository, zlog *zerolog.Logger) (*KeyService, error) {
	if keysrepo == nil {
		return nil, fmt.Errorf("error in New keyservice: pointer to jwtis.KeysRepository is nil")
	}
	log = zlog.With().Str("c", "key_service").Logger()
	return &KeyService{keysRepo: keysrepo}, nil
}

// Register service function to create and register new JWT key set
// returns public keys and error or nil
func (k *KeyService) Register(kid string, opts *jwtis.DefaultOptions) (jwtis.SigEncKeys, error) {
	if k == nil {
		log.Error().Msg("error in Register: keyservice pointer is nil")
		return jwtis.SigEncKeys{}, fmt.Errorf("error in Register: keyservice pointer is nil")
	}
	k.checkOptions(opts)
	return k.keysRepo.NewKey(kid, opts)
}

// UpdateKeys deletes old keys and generates new keys
func (k *KeyService) UpdateKeys(kid string, opts *jwtis.DefaultOptions) (jwtis.SigEncKeys, error) {
	if k == nil {
		return jwtis.SigEncKeys{}, fmt.Errorf("error in Update: keyservice pointer is nil")
	}
	if opts == nil {
		return jwtis.SigEncKeys{}, fmt.Errorf("error in UpdateKeys; nil opts, nothing to update")
	}
	k.mergeUpdateOptions(kid, opts)
	err := k.keysRepo.DelKey(kid)
	if err != nil {
		return jwtis.SigEncKeys{}, fmt.Errorf("error in Update: couldn't delete kid %s: %s", kid, err.Error())
	}
	return k.keysRepo.NewKey(kid, opts)
}

// DelKeys deletes keys for kid
func (k *KeyService) DelKeys(kid string) error {
	if k == nil {
		return fmt.Errorf("error in Register: keyservice pointer is nil")
	}
	return k.keysRepo.DelKey(kid)
}

// PublicKeys returns public keys for certain kid
func (k *KeyService) PublicKeys(kid string) (jwtis.SigEncKeys, error) {
	if k == nil {
		return jwtis.SigEncKeys{}, fmt.Errorf("error in PublicKeys: keyservice pointer is nil")
	}
	return k.keysRepo.GetPublicKeys(kid)
}

func (k *KeyService) checkOptions(opts *jwtis.DefaultOptions) {
	if opts == nil {
		opts = &k.keysRepo.DefaultOptions
	} else {
		if opts.SigAlg == "" {
			opts.SigAlg = k.keysRepo.DefaultOptions.SigAlg
		}
		if opts.SigBits == 0 {
			opts.SigBits = k.keysRepo.DefaultOptions.SigBits
		}
		if opts.EncAlg == "" {
			opts.EncAlg = k.keysRepo.DefaultOptions.EncAlg
		}
		if opts.EncBits == 0 {
			opts.EncBits = k.keysRepo.DefaultOptions.EncBits
		}
		if opts.Expiry == 0 {
			opts.Expiry = k.keysRepo.DefaultOptions.Expiry
		}
		if opts.AuthTTL == 0 {
			opts.AuthTTL = k.keysRepo.DefaultOptions.AuthTTL
		}
		if opts.RefreshTTL == 0 {
			opts.RefreshTTL = k.keysRepo.DefaultOptions.RefreshTTL
		}
		if opts.RefreshStrategy == "" {
			opts.RefreshStrategy = k.keysRepo.DefaultOptions.RefreshStrategy
		}
	}
}

func (k *KeyService) mergeUpdateOptions(kid string, opts *jwtis.DefaultOptions) error {
	if opts == nil {
		return fmt.Errorf("error in mergeUpdateOptions; nil opts, nothing to update")
	}
	ok, keysSet, err := k.keysRepo.KeyExists([]byte(kid))
	if err != nil {
		return fmt.Errorf("error in mergeUpdateOptions checking key existance: %s", err.Error())
	}

	if ok {
		if opts.SigAlg == "" {
			opts.SigAlg = keysSet.SigOpts.Alg
		}
		if opts.SigBits == 0 {
			opts.SigBits = keysSet.SigOpts.Bits
		}
		if opts.EncAlg == "" {
			opts.EncAlg = keysSet.EncOpts.Alg
		}
		if opts.EncBits == 0 {
			opts.EncBits = keysSet.EncOpts.Bits
		}
		if opts.Expiry == 0 {
			opts.Expiry = time.Until(keysSet.Expiry.Time())
		}
		if opts.AuthTTL == 0 {
			opts.AuthTTL = keysSet.AuthTTL
		}
		if opts.RefreshTTL == 0 {
			opts.RefreshTTL = keysSet.RefreshTTL
		}
		if opts.RefreshStrategy == "" {
			opts.RefreshStrategy = keysSet.RefreshStrategy
		}
		return nil
	}
	k.checkOptions(opts)
	return nil
}
