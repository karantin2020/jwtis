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
func (s *JWTService) NewJWT(kid string, claims map[string]interface{},
	ttl ...time.Duration) (*JWTPair, error) {
	log.Info().Msgf("jwt service creating new JWT for kid '%s'", kid)
	ok, jwtset, err := s.keysRepo.KeyExists([]byte(kid))
	if err != nil {
		return nil, fmt.Errorf("error in NewJWT: %s", err.Error())
	}
	if !ok {
		log.Info().Err(err).Bool("ok", ok).Msgf("key exists response: '%#v'", *jwtset)
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
	inttl := make([]time.Duration, 2)
	copy(inttl, ttl)
	if len(ttl) < 2 {
		inttl[1] = jwtset.RefreshTTL
	}
	if len(ttl) < 1 {
		inttl[0] = jwtset.AuthTTL
	}

	privKeys, err := s.keysRepo.GetPrivateKeys(kid)
	if err != nil {
		return nil, fmt.Errorf("error in NewJWT get private keys: %s", err.Error())
	}
	return s.newTokenPair(&privKeys, claims, inttl...)
}

// RenewJWT returns pair of old refresh token and new auth token
func (s *JWTService) RenewJWT(kid string, refresh string, ttl ...time.Duration) (*JWTPair, error) {
	ok, jwtset, err := s.keysRepo.KeyExists([]byte(kid))
	if err != nil {
		return nil, fmt.Errorf("error in RenewJWT: %s", err.Error())
	}
	if !ok {
		return nil, ErrKIDNotExists
	}
	pubKeys := jwtset.Public()
	claimsMap := make(map[string]interface{})
	err = jwtis.ClaimsSignedAndEncrypted(pubKeys.Enc, pubKeys.Sig, refresh, &claimsMap)
	if err != nil {
		return nil, fmt.Errorf("error in RenewJWT parse refresh token: %s", err.Error())
	}

	var mErr jwtis.Error
	if _, ok := claimsMap["jti"]; !ok {
		mErr.Append(fmt.Errorf("jti field is empty"))
	}
	if _, ok := claimsMap["iss"]; !ok {
		mErr.Append(fmt.Errorf("iss field is empty"))
	}
	if len(mErr) != 0 {
		return nil, fmt.Errorf("error in RenewJWT, invalid jwt fields: %s", mErr)
	}

	// define default expiry times
	inttl := make([]time.Duration, 2)
	copy(inttl, ttl)
	if len(ttl) < 2 {
		inttl[1] = jwtset.RefreshTTL
	}
	if len(ttl) < 1 {
		inttl[0] = jwtset.AuthTTL
	}

	// [TODO] Validate and verify refresh token
	// Check refresh token expiration
	// create new auth claims

	privKeys, err := s.keysRepo.GetPrivateKeys(kid)
	if err != nil {
		return nil, fmt.Errorf("error in RenewJWT get private keys: %s", err.Error())
	}
	return s.newTokenPair(&privKeys, claimsMap, inttl...)
}

func (s *JWTService) newTokenPair(privKeys *jwtis.SigEncKeys, claims map[string]interface{},
	ttl ...time.Duration) (*JWTPair, error) {
	if len(ttl) < 2 {
		return nil, fmt.Errorf("jwtservice internal error: invalid ttl array in create token pair")
	}
	id := claims["jti"]
	// define jwt issued at field
	claims["iat"] = jwt.NewNumericDate(time.Now())
	// define jwt not before; equal to issued at field
	claims["nbf"] = claims["iat"]
	var exp jwt.NumericDate
	if vexp, ok := claims["exp"]; !ok {
		exp = jwt.NumericDate(time.Now().Add(ttl[0] * time.Second).Unix())
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
	}
	claims["exp"] = exp
	auth, err := jwtis.JWTSigned(privKeys.Sig, claims)
	if err != nil {
		return nil, fmt.Errorf("error in JWT auth token: %s", err.Error())
	}
	claims["exp"] = jwt.NumericDate(time.Now().Add(ttl[1] * time.Second).Unix())
	refresh, err := jwtis.JWTSignedAndEncrypted(s.defContEnc, privKeys.Enc, privKeys.Sig, claims)
	if err != nil {
		return nil, fmt.Errorf("error in JWT refresh token: %s", err.Error())
	}
	res := &JWTPair{
		ID:           id.(string),
		AccessToken:  auth,
		RefreshToken: refresh,
		Expiry:       exp,
	}
	return res, nil
}
