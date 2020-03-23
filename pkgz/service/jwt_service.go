package service

import (
	// "fmt"
	// "time"

	"fmt"
	"time"

	"github.com/karantin2020/jwtis"
	bluemonday "github.com/microcosm-cc/bluemonday"

	"context"

	"github.com/rs/zerolog"
	uid "github.com/segmentio/ksuid"

	jose "gopkg.in/square/go-jose.v2"

	// errors "github.com/pkg/errors"
	errors "github.com/luno/jettison/errors"
	"github.com/luno/jettison/j"

	jwt "gopkg.in/square/go-jose.v2/jwt"
)

var (
	// ErrInvalidClaimsIssuerCode code
	ErrInvalidClaimsIssuerCode = j.C("ErrInvalidClaimsIssuer")
	// ErrInvalidClaimsExpiryCode code
	ErrInvalidClaimsExpiryCode = j.C("ErrInvalidClaimsExpiry")
	// ErrKIDNotExistsCode code
	ErrKIDNotExistsCode = j.C("ErrKIDNotExists")
	// ErrRefreshTokenExpiredCode code
	ErrRefreshTokenExpiredCode = j.C("ErrRefreshTokenExpired")
	// ErrInvalidRefreshClaimsCode code
	ErrInvalidRefreshClaimsCode = j.C("ErrInvalidRefreshClaims")
	// ErrDecryptRefreshTokenCode code
	ErrDecryptRefreshTokenCode = j.C("ErrDecryptRefreshToken")
	// ErrInternalCode code
	ErrInternalCode = j.C("ErrInternal")
	// ErrInvalidClaimsIssuer if kid in new jwt request is not equal to request claims
	ErrInvalidClaimsIssuer = errors.New("claims issuer field is not equal to request kid", ErrInvalidClaimsIssuerCode)
	// ErrInvalidClaimsExpiry if claims expiry is expired already
	ErrInvalidClaimsExpiry = errors.New("claims expiry field is invalid", ErrInvalidClaimsExpiryCode)
	// ErrKIDNotExists if kid is not in boltdb
	ErrKIDNotExists = errors.New("enc, sig keys are not found", ErrKIDNotExistsCode)
	// ErrRefreshTokenExpired error
	ErrRefreshTokenExpired = errors.New("refresh token is expired", ErrRefreshTokenExpiredCode)
	// ErrInvalidRefreshClaims error
	ErrInvalidRefreshClaims = errors.New("refresh token claim are invalid", ErrInvalidRefreshClaimsCode)
	// ErrDecryptRefreshToken err
	ErrDecryptRefreshToken = errors.New("refresh token couldn't be decrypted", ErrDecryptRefreshTokenCode)
	// ErrInternal err
	ErrInternal = errors.New("internal error", ErrInternalCode)
)

// JWTPair holds auth and refresh tokens
type JWTPair struct {
	ID           string          `json:"id"`
	AccessToken  string          `json:"access_token"`            // Short lived auth token
	RefreshToken string          `json:"refresh_token,omitempty"` // Long lived refresh token
	Expiry       jwt.NumericDate `json:"expiry,omitempty"`
}

const (
	// StrategyRefreshBoth refresh strategy to issue refresh token on every access token renew
	StrategyRefreshBoth = "refreshBoth"
	// StrategyRefreshOnExpire refresh strategy to issue refresh token if it's expiration time is close
	StrategyRefreshOnExpire = "refreshOnExpire"
	// StrategyNoRefresh refresh strategy means refresh token issue must be explicit, only by calling NewJWT
	StrategyNoRefresh = "noRefresh"
)

// JWTService implements server-side jwt logic
type JWTService interface {
	// NewJWT returns pair of new auth and refresh tokens
	// ttl is a list of auth and refresh tokens valid time
	NewJWT(ctx context.Context, kid string, claims map[string]interface{}) (*JWTPair, error)
	// RenewJWT returns pair of old refresh token and new auth token
	RenewJWT(ctx context.Context, kid, refresh, refreshStrategy string) (*JWTPair, error)
}

type jwtService struct {
	keysRepo   *jwtis.KeysRepository
	defContEnc jose.ContentEncryption
}

// NewJWTService returns pointer to new JWTService instance and error
func NewJWTService(keysrepo *jwtis.KeysRepository, zlog zerolog.Logger, contEnc jose.ContentEncryption) (JWTService, error) {
	if keysrepo == nil {
		return nil, errors.Wrap(ErrInternal, "pointer to jwtis.KeysRepository is nil", ErrInternalCode)
	}
	var svc JWTService
	{
		svc = &jwtService{
			keysRepo:   keysrepo,
			defContEnc: contEnc,
		}
		svc = JWTLoggingMiddleware(zlog.With().Str("package", "jwt_service").Logger())(svc)
	}
	return svc, nil
}

// NewJWT returns pair of new auth and refresh tokens
// ttl is a list of auth and refresh tokens valid time
func (s jwtService) NewJWT(ctx context.Context, kid string, claims map[string]interface{}) (*JWTPair, error) {
	ok, jwtset, err := s.keysRepo.KeyExists([]byte(kid))
	if err != nil {
		return nil, fmt.Errorf("error in NewJWT: %s", err.Error())
	}
	if !ok {
		return nil, errors.Wrap(ErrKIDNotExists, "found no keys", j.KS("kid", kid), ErrKIDNotExistsCode)
	}

	sanitize(claims)

	// define jwt id
	if jti, ok := claims["jti"]; !ok || jti.(string) == "" {
		claimid, err := uid.NewRandom()
		if err != nil {
			return nil, errors.Wrap(ErrInternal, err.Error(), j.KS("cause", "ksuid.NewRandom"), ErrInternalCode)
		}
		claims["jti"] = claimid.String()
	}
	// define jwt issuer
	if iss, ok := claims["iss"]; !ok || iss.(string) == "" {
		claims["iss"] = string(kid)
	}
	// define default expiry times
	ttl := [2]time.Duration{jwtset.AuthTTL, jwtset.RefreshTTL}

	privKeys, err := s.keysRepo.GetPrivateKeys(kid)
	if err != nil {
		return nil, fmt.Errorf("error in NewJWT get private keys: %s", err.Error())
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = jwt.NewNumericDate(time.Now())
	}
	if _, ok := claims["nbf"]; !ok {
		claims["nbf"] = claims["iat"]
	}

	var exp jwt.NumericDate
	if vexp, ok := claims["exp"]; !ok {
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
			return nil, fmt.Errorf("error in JWT token exp type assertion")
		}
		if int64(exp) != 0 {
			if time.Now().After(exp.Time()) {
				return nil, fmt.Errorf("error in NewJWT: exp %v is expired", exp.Time())
			}
		}
	}
	claims["exp"] = &exp
	auth, err := jwtis.JWTSigned(&privKeys.Sig, claims)
	if err != nil {
		return nil, fmt.Errorf("error in JWT auth token: %s", err.Error())
	}
	claims["exp"] = jwt.NewNumericDate(time.Now().Add(ttl[1]))
	refresh, err := jwtis.JWTSignedAndEncrypted(s.defContEnc, &privKeys.Enc, &privKeys.Sig, claims)
	if err != nil {
		return nil, fmt.Errorf("error in JWT refresh token: %s", err.Error())
	}
	res := &JWTPair{
		ID:           claims["jti"].(string),
		AccessToken:  auth,
		RefreshToken: refresh,
		Expiry:       exp,
	}

	return res, nil
}

// RenewJWT returns pair of old refresh token and new auth token
func (s jwtService) RenewJWT(ctx context.Context, kid, refresh, refreshStrategy string) (*JWTPair, error) {
	ok, jwtset, err := s.keysRepo.KeyExists([]byte(kid))
	if err != nil {
		return nil, fmt.Errorf("error in RenewJWT: %s", err.Error())
	}
	if !ok {
		return nil, ErrKIDNotExists
	}
	pubSig := jwtset.Sig.Public()
	claimsMap := make(map[string]interface{})
	err = jwtis.ClaimsSignedAndEncrypted(&jwtset.Enc, &pubSig, refresh, &claimsMap)
	if err != nil {
		return nil, ErrDecryptRefreshToken
	}

	var mErr jwtis.Error
	if _, ok := claimsMap["jti"]; !ok {
		mErr.Append(fmt.Errorf("jti field is empty"))
	}
	if _, ok := claimsMap["iss"]; !ok {
		mErr.Append(fmt.Errorf("iss field is empty"))
	}
	if _, ok := claimsMap["iat"]; !ok {
		mErr.Append(fmt.Errorf("iat field is empty"))
	}
	if _, ok := claimsMap["nbf"]; !ok {
		mErr.Append(fmt.Errorf("nbf field is empty"))
	}
	var nExp jwt.NumericDate
	if sExp, ok := claimsMap["exp"]; !ok {
		mErr.Append(fmt.Errorf("exp field is empty"))
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
			mErr.Append(fmt.Errorf("error in renewJWT: token exp type assertion"))
		}
	}
	if nExp == 0 {
		mErr.Append(fmt.Errorf("error in renewJWT: zero value of exp claim"))
	}
	if time.Now().After(time.Unix(int64(nExp), 0)) {
		return nil, ErrRefreshTokenExpired
	}
	if len(mErr) != 0 {
		return nil, ErrInvalidRefreshClaims
	}

	// define default expiry times
	ttl := [2]time.Duration{jwtset.AuthTTL, jwtset.RefreshTTL}

	// [TODO] Validate and verify refresh token
	// Check refresh token expiration
	// create new auth claims

	claimsMap["exp"] = jwt.NewNumericDate(time.Now().Add(ttl[0]))
	auth, err := jwtis.JWTSigned(&jwtset.Sig, claimsMap)
	if err != nil {
		return nil, fmt.Errorf("error in RenewJWT: auth token: %s", err.Error())
	}

	if jwtset.RefreshStrategy == StrategyRefreshBoth || refreshStrategy == StrategyRefreshBoth {
		claimsMap["exp"] = jwt.NewNumericDate(time.Now().Add(ttl[1]))
		refresh, err = jwtis.JWTSignedAndEncrypted(s.defContEnc, &jwtset.Enc, &jwtset.Sig, claimsMap)
		if err != nil {
			return nil, fmt.Errorf("error in RenewJWT: refresh token: %s", err.Error())
		}
	}
	if jwtset.RefreshStrategy == StrategyRefreshOnExpire || refreshStrategy == StrategyRefreshOnExpire {
		if float64(float64(time.Second*time.Duration(int64(nExp)-time.Now().Unix()))/float64(ttl[1])) < 0.3 {
			claimsMap["exp"] = jwt.NewNumericDate(time.Now().Add(ttl[1]))
			refresh, err = jwtis.JWTSignedAndEncrypted(s.defContEnc, &jwtset.Enc, &jwtset.Sig, claimsMap)
			if err != nil {
				return nil, fmt.Errorf("error in RenewJWT: refresh token: %s", err.Error())
			}
		}
	}

	res := &JWTPair{
		ID:           claimsMap["jti"].(string),
		AccessToken:  auth,
		RefreshToken: refresh,
		Expiry:       *(claimsMap["exp"].(*jwt.NumericDate)),
	}

	return res, nil
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
