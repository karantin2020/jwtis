package keys

import (
	"context"
	"time"

	"github.com/karantin2020/jwtis"
	api "github.com/karantin2020/jwtis/api/keys/v1"
	"github.com/karantin2020/jwtis/pkg/errdef"
	"github.com/karantin2020/jwtis/pkg/repos/keys"
	"github.com/karantin2020/jwtis/pkg/services"
	errors "github.com/pkg/errors"
	"google.golang.org/grpc"
	jose "gopkg.in/square/go-jose.v2"

	// bluemonday "github.com/microcosm-cc/bluemonday"
	// uid "github.com/segmentio/ksuid"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

// Service interface declares keys service type
type Service interface {
	Auth(ctx context.Context, req *AuthRequest) (*AuthResponse, error)
	Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error)
	UpdateKeys(ctx context.Context, req *UpdateKeysRequest) (*UpdateKeysResponse, error)
	ListKeys(ctx context.Context, req *ListKeysRequest) ([]*ListKeysResponse, error)
	DelKeys(ctx context.Context, req *DelKeysRequest) (*DelKeysResponse, error)
	PublicKeys(ctx context.Context, req *PublicKeysRequest) (*PublicKeysResponse, error)
}

var _ Service = &serviceImpl{}

type serviceImpl struct {
	keysRepo   *keys.Repository
	defContEnc jose.ContentEncryption
}

// newService constructor
func newService(keysrepo *keys.Repository, contEnc jose.ContentEncryption) Service {
	if keysrepo == nil {
		panic(errdef.ErrNullKeysRepo)
	}
	return &serviceImpl{
		keysRepo:   keysrepo,
		defContEnc: contEnc,
	}
}

// Register func registers KeysServer service
func Register() *services.ServiceInfo {
	return &services.ServiceInfo{
		Type: services.GRPCService,
		ID:   services.Keys,
		InitFn: func(ctx context.Context) (interface{}, error) {
			svcCtx, err := services.FromContext(ctx)
			if err != nil {
				return nil, errors.Wrap(errdef.ErrInternal, "keys: service context is not found: "+err.Error())
			}
			svc := newService(svcCtx.KeysRepo, svcCtx.ContEnc)
			keysServer := NewKeysServer(svc, svcCtx.Logger)
			return keysServer, nil
		},
	}
}

func (s *grpcServer) RegisterGRPC(server *grpc.Server) error {
	api.RegisterKeysServer(server, s)
	return nil
}

// Auth server service method
func (s *serviceImpl) Auth(ctx context.Context, req *AuthRequest) (*AuthResponse, error) {
	if s.keysRepo == nil {
		return nil, errdef.ErrNullKeysRepo
	}
	kid := req.KID
	ok, kis, err := s.keysRepo.KeyExists([]byte(kid))
	if err != nil {
		return nil, errors.Wrap(errdef.ErrInternal, "KeyExists error: "+err.Error())
	}
	if !ok {
		return nil, errdef.ErrKIDNotExists
	}

	privKeys, err := s.keysRepo.GetPrivateKeys(kid)
	if err != nil {
		return nil, errors.Wrap(errdef.ErrInternal, "GetPrivateKeys error: "+err.Error())
	}

	claims := make(map[string]interface{})
	claims["kid"] = kid
	claims["iss"] = "JWTIS"
	claims["iat"] = jwt.NewNumericDate(time.Now())
	claims["nbf"] = claims["iat"]
	claims["exp"] = kis.Expiry
	authJWT, err := jwtis.JWTSigned(&privKeys.Sig, claims)
	if err != nil {
		return nil, errors.Wrap(errdef.ErrInternal, "JWTSigned error: "+err.Error())
	}
	return &AuthResponse{
		AuthJWT: authJWT,
	}, nil
}

// Register server service method
func (s *serviceImpl) Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	if s.keysRepo == nil {
		return nil, errdef.ErrNullKeysRepo
	}
	s.checkOptions(req)
	opts := convertKeysOptions(req)
	resp, err := s.keysRepo.NewKey(req.KID, opts)
	if err != nil {
		return nil, errors.Wrap(errdef.ErrInternal, "Register: create new keys error: "+err.Error())
	}
	authJWT, err := s.Auth(ctx, &AuthRequest{
		KID: req.KID,
	})
	if err != nil {
		return nil, errors.Wrap(errdef.ErrInternal, "Register: generate auth token error: "+err.Error())
	}
	return &RegisterResponse{
		KID:     req.KID,
		AuthJWT: authJWT.AuthJWT,
		Keys:    resp,
	}, nil
}

// UpdateKeys server service method
func (s *serviceImpl) UpdateKeys(ctx context.Context, req *UpdateKeysRequest) (*UpdateKeysResponse, error) {
	if s.keysRepo == nil {
		return nil, errdef.ErrNullKeysRepo
	}
	if req == nil {
		return nil, errors.Wrap(errdef.ErrInvalidArgument, "UpdateKeys: UpdateKeysRequest pointer is nil")
	}
	kid := req.KID
	s.mergeUpdateOptions(kid, req)
	err := s.keysRepo.DelKey(kid)
	if err != nil {
		return nil, errors.Wrap(errdef.ErrInternal, "UpdateKeys: error delete keys: "+err.Error())
	}
	resp, err := s.keysRepo.NewKey(kid, &keys.DefaultOptions{
		SigAlg:          req.SigAlg,
		SigBits:         req.SigBits,
		EncAlg:          req.EncAlg,
		EncBits:         req.EncBits,
		ContEnc:         req.ContEnc,
		Expiry:          req.Expiry,
		AuthTTL:         req.AuthTTL,
		RefreshTTL:      req.RefreshTTL,
		RefreshStrategy: req.RefreshStrategy,
	})
	if err != nil {
		return nil, errors.Wrap(errdef.ErrInternal, "UpdateKeys: error create new keys: "+err.Error())
	}
	authJWT, err := s.Auth(ctx, &AuthRequest{
		KID: req.KID,
	})
	if err != nil {
		return nil, errors.Wrap(errdef.ErrInternal, "UpdateKeys: generate auth token error: "+err.Error())
	}
	return &UpdateKeysResponse{
		KID:     req.KID,
		AuthJWT: authJWT.AuthJWT,
		Keys:    resp,
	}, nil
}

func (s *serviceImpl) ListKeys(ctx context.Context, req *ListKeysRequest) ([]*ListKeysResponse, error) {
	if s.keysRepo == nil {
		return nil, errdef.ErrNullKeysRepo
	}
	resp, err := s.keysRepo.ListKeys()
	if err != nil {
		return nil, errors.Wrap(errdef.ErrInternal, "listKeys: error request keys: "+err.Error())
	}
	listResp := make([]*ListKeysResponse, len(resp), len(resp))
	for i := range resp {
		listResp[i] = &ListKeysResponse{
			KID:  resp[i].KID,
			Keys: resp[i],
		}
	}
	return listResp, nil
}

// DelKeys server service method
func (s *serviceImpl) DelKeys(ctx context.Context, req *DelKeysRequest) (*DelKeysResponse, error) {
	if s.keysRepo == nil {
		return nil, errdef.ErrNullKeysRepo
	}
	err := s.keysRepo.DelKey(req.KID)
	if err != nil {
		return nil, errors.Wrap(errdef.ErrInternal, "DelKeys: error delete keys: "+err.Error())
	}
	return &DelKeysResponse{}, nil
}

// PublicKeys server service method
func (s *serviceImpl) PublicKeys(ctx context.Context, req *PublicKeysRequest) (*PublicKeysResponse, error) {
	if s.keysRepo == nil {
		return nil, errdef.ErrNullKeysRepo
	}
	resp, err := s.keysRepo.GetPublicKeys(req.KID)
	if err != nil {
		return nil, errors.Wrap(errdef.ErrInternal, "PublicKeys: error fetch publick keys: "+err.Error())
	}
	return &PublicKeysResponse{
		KID:  req.KID,
		Keys: resp,
	}, nil
}

func (s *serviceImpl) checkOptions(opts *RegisterRequest) {
	defs := &s.keysRepo.DefaultOptions
	if opts == nil {
		opts = &RegisterRequest{
			SigAlg:          defs.SigAlg,
			SigBits:         defs.SigBits,
			EncAlg:          defs.EncAlg,
			EncBits:         defs.EncBits,
			Expiry:          defs.Expiry,
			AuthTTL:         defs.AuthTTL,
			RefreshTTL:      defs.RefreshTTL,
			RefreshStrategy: defs.RefreshStrategy,
		}
	} else {
		if opts.SigAlg == "" {
			opts.SigAlg = defs.SigAlg
		}
		if opts.SigBits == 0 {
			opts.SigBits = defs.SigBits
		}
		if opts.EncAlg == "" {
			opts.EncAlg = defs.EncAlg
		}
		if opts.EncBits == 0 {
			opts.EncBits = defs.EncBits
		}
		if opts.Expiry == 0 {
			opts.Expiry = defs.Expiry
		}
		if opts.AuthTTL == 0 {
			opts.AuthTTL = defs.AuthTTL
		}
		if opts.RefreshTTL == 0 {
			opts.RefreshTTL = defs.RefreshTTL
		}
		if opts.RefreshStrategy == "" {
			opts.RefreshStrategy = defs.RefreshStrategy
		}
	}
}

func (s *serviceImpl) mergeUpdateOptions(kid string, opts *UpdateKeysRequest) error {
	if opts == nil {
		return errors.Wrap(errdef.ErrInternal, "mergeUpdateOptions: nil opts, nothing to update")
	}
	ok, keysSet, err := s.keysRepo.KeyExists([]byte(kid))
	if err != nil {
		return errors.Wrap(errdef.ErrInternal, "mergeUpdateOptions: checking key existence error: "+err.Error())
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
	s.checkOptions(&RegisterRequest{
		KID:             opts.KID,
		SigAlg:          opts.SigAlg,
		EncAlg:          opts.EncAlg,
		SigBits:         opts.SigBits,
		EncBits:         opts.EncBits,
		Expiry:          opts.Expiry,
		AuthTTL:         opts.AuthTTL,
		RefreshTTL:      opts.RefreshTTL,
		RefreshStrategy: opts.RefreshStrategy,
	})
	return nil
}

func convertKeysOptions(opts *RegisterRequest) *keys.DefaultOptions {
	return &keys.DefaultOptions{
		SigAlg:          opts.SigAlg,
		SigBits:         opts.SigBits,
		EncAlg:          opts.EncAlg,
		EncBits:         opts.EncBits,
		Expiry:          opts.Expiry,
		AuthTTL:         opts.AuthTTL,
		RefreshTTL:      opts.RefreshTTL,
		RefreshStrategy: opts.RefreshStrategy,
	}
}
