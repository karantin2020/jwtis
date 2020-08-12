package jwt

import (
	"context"
	"time"

	"github.com/karantin2020/jwtis"
	api "github.com/karantin2020/jwtis/api/jwt/v1"
	"github.com/karantin2020/jwtis/pkg/errdef"
	"github.com/karantin2020/jwtis/pkg/repos/keys"
	"github.com/karantin2020/jwtis/pkg/services"
	errors "github.com/pkg/errors"
	"google.golang.org/grpc"
	jose "gopkg.in/square/go-jose.v2"

	bluemonday "github.com/microcosm-cc/bluemonday"
	uid "github.com/segmentio/ksuid"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

const (
	// StrategyRefreshBoth refresh strategy to issue refresh token on every access token renew
	StrategyRefreshBoth = "refreshBoth"
	// StrategyRefreshOnExpire refresh strategy to issue refresh token if it's expiration time is close
	StrategyRefreshOnExpire = "refreshOnExpire"
	// StrategyNoRefresh refresh strategy means refresh token issue must be explicit, only by calling NewJWT
	StrategyNoRefresh = "noRefresh"
)

// Service interface type
type Service interface {
	NewJWT(ctx context.Context, req *NewJWTRequest) (*NewJWTResponse, error)
	RenewJWT(ctx context.Context, req *RenewJWTRequest) (*RenewJWTResponse, error)
	RevokeJWT(ctx context.Context, req *RevokeJWTRequest) (*RevokeJWTResponse, error)
}

var _ Service = &serviceImpl{}

type serviceImpl struct {
	keysRepo   *keys.Repository
	defContEnc jose.ContentEncryption
}

// newService constructor
func newService(keysrepo *keys.Repository) Service {
	if keysrepo == nil {
		panic(errdef.ErrNullKeysRepo)
	}
	return &serviceImpl{
		keysRepo: keysrepo,
	}
}

// Register func registers KeysServer service
func Register() *services.ServiceInfo {
	return &services.ServiceInfo{
		Type: services.GRPCService,
		ID:   services.JWT,
		InitFn: func(ctx context.Context) (interface{}, error) {
			svcCtx, err := services.FromContext(ctx)
			if err != nil {
				return nil, errors.Wrap(errdef.ErrInternal, "jwt: service context is not found: "+err.Error())
			}
			svc := newService(svcCtx.KeysRepo)
			keysServer := NewJWTServer(svc, svcCtx.Logger)
			return keysServer, nil
		},
	}
}

func (s *grpcServer) RegisterGRPC(server *grpc.Server) error {
	api.RegisterJWTServer(server, s)
	return nil
}

// NewJWT server service method
func (s *serviceImpl) NewJWT(ctx context.Context, req *NewJWTRequest) (*NewJWTResponse, error) {
	if s.keysRepo == nil {
		return nil, errdef.ErrNullKeysRepo
	}
	kid := req.KID
	ok, keysSet, err := s.keysRepo.KeyExists([]byte(kid))
	if err != nil {
		return nil, errors.Wrap(errdef.ErrInternal, "NewJWT: check KeyExists error: "+err.Error())
	}
	if !ok {
		return nil, errors.Wrapf(errdef.ErrInvalidArgument, "NewJWT: found no keys with kid '%s'", kid)
	}

	sanitize(req.Claims)

	// define jwt id
	if jti, ok := req.Claims["jti"]; !ok || jti.(string) == "" {
		claimid, err := uid.NewRandom()
		if err != nil {
			return nil, errors.Wrap(errdef.ErrInternal, "NewJWT: error generating new token id: "+err.Error())
		}
		req.Claims["jti"] = claimid.String()
	}
	// define jwt issuer
	if iss, ok := req.Claims["iss"]; !ok || iss.(string) == "" {
		req.Claims["iss"] = string(kid)
	}
	// define default expiry times
	ttl := [2]time.Duration{keysSet.AuthTTL, keysSet.RefreshTTL}

	privKeys, err := s.keysRepo.GetPrivateKeys(kid)
	if err != nil {
		return nil, errors.Wrap(errdef.ErrInternal, "NewJWT: GetPrivateKeys error: "+err.Error())
	}
	if _, ok := req.Claims["iat"]; !ok {
		req.Claims["iat"] = jwt.NewNumericDate(time.Now())
	}
	if _, ok := req.Claims["nbf"]; !ok {
		req.Claims["nbf"] = req.Claims["iat"]
	}

	var exp jwt.NumericDate
	if vexp, ok := req.Claims["exp"]; !ok {
		exp = jwt.NumericDate(time.Now().Add(ttl[0]).Unix())
	} else {
		switch tExp := vexp.(type) {
		case float64:
			exp = jwt.NumericDate(tExp)
		case int64:
			exp = jwt.NumericDate(tExp)
		case int:
			exp = jwt.NumericDate(tExp)
		case jwt.NumericDate:
			exp = tExp
		default:
			return nil, errors.Wrap(errdef.ErrInvalidArgument, "NewJWT: invalid exp type in claims")
		}
		if int64(exp) != 0 {
			if time.Now().After(exp.Time()) {
				return nil, errors.Wrap(errdef.ErrInvalidArgument, "NewJWT: token (exp field) is expired")
			}
		}
	}
	req.Claims["exp"] = &exp
	auth, err := jwtis.JWTSigned(&privKeys.Sig, req.Claims)
	if err != nil {
		return nil, errors.Wrap(errdef.ErrInternal, "NewJWT: JWTSigned error: "+err.Error())
	}
	req.Claims["exp"] = jwt.NewNumericDate(time.Now().Add(ttl[1]))
	refresh, err := jwtis.JWTSignedAndEncrypted(privKeys.ContEnc, &privKeys.Enc, &privKeys.Sig, req.Claims)
	if err != nil {
		return nil, errors.Wrap(errdef.ErrInternal, "NewJWT: JWT refresh error: "+err.Error())
	}
	res := &NewJWTResponse{
		ID:           req.Claims["jti"].(string),
		AccessToken:  auth,
		RefreshToken: refresh,
		Expiry:       exp,
	}

	return res, nil
}

// RenewJWT server service method
func (s *serviceImpl) RenewJWT(ctx context.Context, req *RenewJWTRequest) (*RenewJWTResponse, error) {
	if s.keysRepo == nil {
		return nil, errdef.ErrNullKeysRepo
	}
	kid := req.KID
	refreshToken := req.RefreshToken
	refreshStrategy := req.RefreshStrategy
	ok, keysSet, err := s.keysRepo.KeyExists([]byte(kid))
	if err != nil {
		return nil, errors.Wrap(errdef.ErrInternal, "RenewJWT: KeyExists error: "+err.Error())
	}
	if !ok {
		return nil, errdef.ErrKIDNotExists
	}
	pubSig := keysSet.Sig.Public()
	claimsMap := make(map[string]interface{})
	err = jwtis.ClaimsSignedAndEncrypted(&keysSet.Enc, &pubSig, refreshToken, &claimsMap)
	if err != nil {
		return nil, errdef.ErrDecryptRefreshToken
	}

	var mErr jwtis.Error
	if _, ok := claimsMap["jti"]; !ok {
		mErr.Append(errors.Wrap(errdef.ErrInvalidRefreshToken, "RenewJWT: jti field is empty"))
	}
	if _, ok := claimsMap["iss"]; !ok {
		mErr.Append(errors.Wrap(errdef.ErrInvalidRefreshToken, "RenewJWT: iss field is empty"))
	}
	if _, ok := claimsMap["iat"]; !ok {
		mErr.Append(errors.Wrap(errdef.ErrInvalidRefreshToken, "RenewJWT: iat field is empty"))
	}
	if _, ok := claimsMap["nbf"]; !ok {
		mErr.Append(errors.Wrap(errdef.ErrInvalidRefreshToken, "RenewJWT: nbf field is empty"))
	}
	var nExp jwt.NumericDate
	if sExp, ok := claimsMap["exp"]; !ok {
		mErr.Append(errors.Wrap(errdef.ErrInvalidRefreshToken, "RenewJWT: exp field is empty"))
	} else {
		switch tExp := sExp.(type) {
		case float64:
			nExp = jwt.NumericDate(tExp)
		case int64:
			nExp = jwt.NumericDate(tExp)
		case int:
			nExp = jwt.NumericDate(tExp)
		case jwt.NumericDate:
			nExp = tExp
		default:
			mErr.Append(errors.Wrap(errdef.ErrInvalidRefreshToken, "RenewJWT: error in renewJWT: token exp type assertion"))
		}
	}
	// exp field must not be negative
	if nExp < 1 {
		mErr.Append(errors.Wrap(errdef.ErrInvalidRefreshToken, "RenewJWT: error in renewJWT: zero value of exp claim"))
	}
	if time.Now().After(time.Unix(int64(nExp), 0)) {
		return nil, errdef.ErrRefreshTokenExpired
	}
	if len(mErr) != 0 {
		return nil, errors.Wrap(errdef.ErrInvalidRefreshClaims, mErr.Error())
	}

	// define default expiry times
	ttl := [2]time.Duration{keysSet.AuthTTL, keysSet.RefreshTTL}

	// [TODO] Validate and verify refresh token
	// Check refresh token expiration
	// create new auth claims

	claimsMap["exp"] = jwt.NewNumericDate(time.Now().Add(ttl[0]))
	auth, err := jwtis.JWTSigned(&keysSet.Sig, claimsMap)
	if err != nil {
		return nil, errors.Wrap(errdef.ErrInternal, "RenewJWT: JWTSigned error: "+err.Error())
	}

	if keysSet.RefreshStrategy == StrategyRefreshBoth || refreshStrategy == StrategyRefreshBoth {
		claimsMap["exp"] = jwt.NewNumericDate(time.Now().Add(ttl[1]))
		refreshToken, err = jwtis.JWTSignedAndEncrypted(keysSet.ContEnc, &keysSet.Enc, &keysSet.Sig, claimsMap)
		if err != nil {
			return nil, errors.Wrap(errdef.ErrInternal, "RenewJWT: JWTSignedAndEncrypted error "+err.Error())
		}
	}
	if keysSet.RefreshStrategy == StrategyRefreshOnExpire || refreshStrategy == StrategyRefreshOnExpire {
		if float64(float64(time.Second*time.Duration(int64(nExp)-time.Now().Unix()))/float64(ttl[1])) < 0.3 {
			claimsMap["exp"] = jwt.NewNumericDate(time.Now().Add(ttl[1]))
			refreshToken, err = jwtis.JWTSignedAndEncrypted(keysSet.ContEnc, &keysSet.Enc, &keysSet.Sig, claimsMap)
			if err != nil {
				return nil, errors.Wrap(errdef.ErrInternal, "RenewJWT: JWTSignedAndEncrypted error "+err.Error())
			}
		}
	}

	res := &RenewJWTResponse{
		ID:           claimsMap["jti"].(string),
		AccessToken:  auth,
		RefreshToken: refreshToken,
		Expiry:       *(claimsMap["exp"].(*jwt.NumericDate)),
	}

	return res, nil
}

// RevokeJWT server service method
func (s *serviceImpl) RevokeJWT(ctx context.Context, req *RevokeJWTRequest) (*RevokeJWTResponse, error) {
	if s.keysRepo == nil {
		return nil, errdef.ErrNullKeysRepo
	}
	return nil, errdef.ErrUnimplemented
}

func sanitize(m map[string]interface{}) {
	p := bluemonday.StrictPolicy()
	for k, v := range m {
		switch t := v.(type) {
		case string:
			m[k] = p.Sanitize(t)
		case []byte:
			m[k] = p.SanitizeBytes(t)
		default:
		}
	}
}
