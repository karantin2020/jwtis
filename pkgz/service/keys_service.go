package service

import (
	"context"
	"time"

	"github.com/karantin2020/jwtis"
	errors "github.com/luno/jettison/errors"
	"github.com/luno/jettison/j"
	"github.com/rs/zerolog"
)

var (
	// ErrInvalidKeysRepoCode error code
	ErrInvalidKeysRepoCode = j.C("ErrInvalidKeysRepo")
	// ErrInvalidKeysRepo error
	ErrInvalidKeysRepo = errors.New("keyservice pointer is nil", ErrInvalidKeysRepoCode)
	// ErrInvalidOptionsCode error code
	ErrInvalidOptionsCode = j.C("ErrInvalidOptions")
	// ErrInvalidOptions error
	ErrInvalidOptions = errors.New("keyservice pointer is nil", ErrInvalidOptionsCode)
)

// KeysService implements server-side jwt logic
type KeysService interface {
	Register(ctx context.Context, kid string, opts *jwtis.DefaultOptions) (*jwtis.SigEncKeys, error)
	UpdateKeys(ctx context.Context, kid string, opts *jwtis.DefaultOptions) (*jwtis.SigEncKeys, error)
	ListKeys(ctx context.Context) ([]jwtis.KeysInfoSet, error)
	DelKeys(ctx context.Context, kid string) error
	PublicKeys(ctx context.Context, kid string) (*jwtis.SigEncKeys, error)
}

type keysService struct {
	keysRepo *jwtis.KeysRepository
}

// NewKeyService returns pointer to new JWTService instance and error
func NewKeyService(keysrepo *jwtis.KeysRepository, zlog *zerolog.Logger) (KeysService, error) {
	if keysrepo == nil {
		return nil, ErrInvalidKeysRepo
	}
	var svc KeysService
	{
		svc = &keysService{
			keysRepo: keysrepo,
		}
		svc = KeysLoggingMiddleware(zlog.With().Str("package", "keys_service").Logger())(svc)
	}
	return svc, nil
}

// Register service function to create and register new JWT key set
// returns public keys and error or nil
func (k *keysService) Register(ctx context.Context, kid string, opts *jwtis.DefaultOptions) (*jwtis.SigEncKeys, error) {
	if k == nil {
		return nil, ErrInvalidKeysRepo
	}
	k.checkOptions(opts)
	resp, err := k.keysRepo.NewKey(kid, opts)
	return resp, errors.Wrap(err, "operation error", ErrInternalCode)
}

// UpdateKeys deletes old keys and generates new keys
func (k *keysService) UpdateKeys(ctx context.Context, kid string, opts *jwtis.DefaultOptions) (*jwtis.SigEncKeys, error) {
	if k == nil {
		return nil, ErrInvalidKeysRepo
	}
	if opts == nil {
		return nil, ErrInvalidOptions
	}
	k.mergeUpdateOptions(kid, opts)
	err := k.keysRepo.DelKey(kid)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't delete key", ErrInternalCode)
	}
	resp, err := k.keysRepo.NewKey(kid, opts)
	return resp, errors.Wrap(err, "operation error", ErrInternalCode)
}

// ListKeys returns all registered keys
func (k *keysService) ListKeys(ctx context.Context) ([]jwtis.KeysInfoSet, error) {
	if k == nil {
		return nil, ErrInvalidKeysRepo
	}
	resp, err := k.keysRepo.ListKeys()
	return resp, errors.Wrap(err, "operation error", ErrInternalCode)
}

// DelKeys deletes keys for kid
func (k *keysService) DelKeys(ctx context.Context, kid string) error {
	if k == nil {
		return ErrInvalidKeysRepo
	}
	err := k.keysRepo.DelKey(kid)
	return errors.Wrap(err, "operation error", ErrInternalCode)
}

// PublicKeys returns public keys for certain kid
func (k *keysService) PublicKeys(ctx context.Context, kid string) (*jwtis.SigEncKeys, error) {
	if k == nil {
		return nil, ErrInvalidKeysRepo
	}
	resp, err := k.keysRepo.GetPublicKeys(kid)
	return resp, errors.Wrap(err, "operation error", ErrInternalCode)
}

func (k *keysService) checkOptions(opts *jwtis.DefaultOptions) {
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

func (k *keysService) mergeUpdateOptions(kid string, opts *jwtis.DefaultOptions) error {
	if opts == nil {
		return errors.New("error in mergeUpdateOptions; nil opts, nothing to update", ErrInternalCode)
	}
	ok, keysSet, err := k.keysRepo.KeyExists([]byte(kid))
	if err != nil {
		return errors.Wrap(err, "error in mergeUpdateOptions checking key existance", ErrInternalCode)
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
