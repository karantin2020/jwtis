package jwtservice

import (
	"fmt"
	"time"

	"github.com/karantin2020/jwtis"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

var (
	// ErrInvalidClaimsIssuer if kid in new jwt request is not equal to request claims
	ErrInvalidClaimsIssuer = fmt.Errorf("claims issuer field is not equal to request kid")
	// ErrInvalidClaimsExpiry if claims expiry is expired already
	ErrInvalidClaimsExpiry = fmt.Errorf("claims expiry field is invalid")
	// ErrKIDNotExists if kid is not in boltdb
	ErrKIDNotExists = fmt.Errorf("enc, sig keys are not found")
	// ErrRefreshTokenExpired error
	ErrRefreshTokenExpired = fmt.Errorf("refresh token is expired")
	// ErrInvalidRefreshClaims error
	ErrInvalidRefreshClaims = fmt.Errorf("refresh token claim are invalid")
	// ErrDecryptRefreshToken err
	ErrDecryptRefreshToken = fmt.Errorf("refresh token couldn't be decrypted")
)

const (
	// StrategyRefreshBoth refresh strategy to issue refresh token on every access token renew
	StrategyRefreshBoth = "refreshBoth"
	// StrategyRefreshOnExpire refresh strategy to issue refresh token if it's expiration time is close
	StrategyRefreshOnExpire = "refreshOnExpire"
	// StrategyNoRefresh refresh strategy means refresh token issue must be explicit, only by calling NewJWT
	StrategyNoRefresh = "noRefresh"
)

var (
	log zerolog.Logger
)

// JWTPair holds auth and refresh tokens
type JWTPair struct {
	ID           string          `json:"id"`
	AccessToken  string          `json:"access_token"`            // Short lived auth token
	RefreshToken string          `json:"refresh_token,omitempty"` // Long lived refresh token
	Expiry       jwt.NumericDate `json:"expiry,omitempty"`
}

// JWTService implements server-side jwt logic
type JWTService struct {
	keysRepo   *jwtis.KeysRepository
	defContEnc jose.ContentEncryption
}

// New returns pointer to new JWTService instance and error
func New(keysrepo *jwtis.KeysRepository, zlog *zerolog.Logger, contEnc jose.ContentEncryption) (*JWTService, error) {
	if keysrepo == nil {
		return nil, fmt.Errorf("error in New jwtservice: pointer to jwtis.KeysRepository is nil")
	}
	log = zlog.With().Str("c", "jwt_service").Logger()
	return &JWTService{keysRepo: keysrepo, defContEnc: contEnc}, nil
}

// NewJWT returns pair of new auth and refresh tokens
// ttl is a list of auth and refresh tokens valid time
func (s *JWTService) NewJWT(kid string, claims map[string]interface{}) (*JWTPair, error) {
	log.Info().Msgf("jwt service creating new JWT for kid '%s'", kid)
	ok, jwtset, err := s.keysRepo.KeyExists([]byte(kid))
	if err != nil {
		return nil, fmt.Errorf("error in NewJWT: %s", err.Error())
	}
	if !ok {
		log.Error().Err(err).Bool("ok", ok).Msgf("error in NewJWT: keys with kid '%s' don't exist", kid)
		return nil, ErrKIDNotExists
	}

	// define jwt id
	if jti, ok := claims["jti"]; !ok || jti.(string) == "" {
		u1, _ := uuid.NewV1()
		claimid := uuid.NewV5(u1, kid).String()
		claims["jti"] = claimid
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
	auth, err := jwtis.JWTSigned(privKeys.Sig, claims)
	if err != nil {
		return nil, fmt.Errorf("error in JWT auth token: %s", err.Error())
	}
	claims["exp"] = jwt.NewNumericDate(time.Now().Add(ttl[1]))
	refresh, err := jwtis.JWTSignedAndEncrypted(s.defContEnc, privKeys.Enc, privKeys.Sig, claims)
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
func (s *JWTService) RenewJWT(kid, refresh, refreshStrategy string) (*JWTPair, error) {
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

// TODO: Delete old code
// func (s *JWTService) newTokenPair(privKeys *jwtis.SigEncKeys, claims map[string]interface{},
// 	ttl ...time.Duration) (*JWTPair, error) {
// 	if len(ttl) < 2 {
// 		return nil, fmt.Errorf("jwtservice internal error: invalid ttl array in create token pair")
// 	}
// 	id := claims["jti"]
// 	// define jwt issued at field
// 	claims["iat"] = jwt.NewNumericDate(time.Now())
// 	// define jwt not before; equal to issued at field
// 	claims["nbf"] = claims["iat"]
// 	var exp jwt.NumericDate
// 	if vexp, ok := claims["exp"]; !ok {
// 		exp = jwt.NumericDate(time.Now().Add(ttl[0] * time.Second).Unix())
// 	} else {
// 		switch tExp := vexp.(type) {
// 		case float64:
// 			exp = jwt.NumericDate(tExp)
// 		case int64:
// 			exp = jwt.NumericDate(tExp)
// 		case int:
// 			exp = jwt.NumericDate(tExp)
// 		case jwt.NumericDate:
// 			exp = tExp
// 		default:
// 			return nil, fmt.Errorf("error in JWT token exp type assertion")
// 		}
// 	}
// 	claims["exp"] = exp
// 	auth, err := jwtis.JWTSigned(privKeys.Sig, claims)
// 	if err != nil {
// 		return nil, fmt.Errorf("error in JWT auth token: %s", err.Error())
// 	}
// 	claims["exp"] = jwt.NumericDate(time.Now().Add(ttl[1] * time.Second).Unix())
// 	refresh, err := jwtis.JWTSignedAndEncrypted(s.defContEnc, privKeys.Enc, privKeys.Sig, claims)
// 	if err != nil {
// 		return nil, fmt.Errorf("error in JWT refresh token: %s", err.Error())
// 	}
// 	res := &JWTPair{
// 		ID:           id.(string),
// 		AccessToken:  auth,
// 		RefreshToken: refresh,
// 		Expiry:       exp,
// 	}
// 	return res, nil
// }

// AuthJWT returns auth jwt
func (s *JWTService) AuthJWT(kid string) (string, error) {
	log.Info().Msgf("jwt service creating auth JWT for kid '%s'", kid)
	ok, _, err := s.keysRepo.KeyExists([]byte(kid))
	if err != nil {
		return "", fmt.Errorf("error in AuthJWT: %s", err.Error())
	}
	if !ok {
		log.Error().Err(err).Bool("ok", ok).Msgf("error in AuthJWT: keys with kid '%s' don't exist", kid)
		return "", ErrKIDNotExists
	}

	privKeys, err := s.keysRepo.GetPrivateKeys(kid)
	if err != nil {
		return "", fmt.Errorf("error in AuthJWT get private keys: %s", err.Error())
	}

	claims := make(map[string]interface{})
	claims["kid"] = kid
	claims["iss"] = "JWTIS"
	authJWT, err := jwtis.JWTSigned(privKeys.Sig, claims)
	if err != nil {
		log.Error().Err(err).Msg("error in AuthJWT: sign error")
		return "", fmt.Errorf("error in AuthJWT: %s", err.Error())
	}

	return authJWT, nil
}
