package jwtservice

import (
	"fmt"
	"time"

	"github.com/karantin2020/jwtis"
	uuid "github.com/satori/go.uuid"
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

// JWTPair holds auth and refresh tokens
type JWTPair struct {
	AuthToken    string `json:"auth_token"`    // Short lived auth token
	RefreshToken string `json:"refresh_token"` // Long lived refresh token
}

// JWTService implements server-side jwt logic
type JWTService struct {
	keysRepo *jwtis.KeysRepository
}

// New returns pointer to new JWTService instance and error
func New(keysrepo *jwtis.KeysRepository) (*JWTService, error) {
	if keysrepo == nil {
		return nil, fmt.Errorf("error in New jwtservice: pointer to jwtis.KeysRepository is nil")
	}
	return &JWTService{keysRepo: keysrepo}, nil
}

// NewJWT returns pair of new auth and refresh tokens
// ttl is a list of auth and refresh tokens valid time
func (s *JWTService) NewJWT(kid string, claims map[string]interface{},
	ttl ...time.Duration) (*JWTPair, error) {
	ok, jwtset, err := s.keysRepo.KeyExists([]byte(kid))
	if err != nil {
		return nil, fmt.Errorf("error in NewJWT: %s", err.Error())
	}
	if !ok {
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
	return newTokenPair(&privKeys, claims, inttl...)
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
	return newTokenPair(&privKeys, claimsMap, inttl...)
}

func newTokenPair(privKeys *jwtis.SigEncKeys, claims map[string]interface{},
	ttl ...time.Duration) (*JWTPair, error) {
	if len(ttl) < 2 {
		return nil, fmt.Errorf("jwtservice internal error: invalid ttl array in create token pair")
	}
	// define jwt issued at field
	claims["iat"] = jwt.NewNumericDate(time.Now())
	// define jwt not before; equal to issued at field
	claims["nbf"] = claims["iat"]
	claims["exp"] = jwt.NumericDate(time.Now().Add(ttl[0]).Unix())
	auth, err := jwtis.JWTSigned(privKeys.Sig, claims)
	if err != nil {
		return nil, fmt.Errorf("error in NewJWT create auth token: %s", err.Error())
	}
	claims["exp"] = jwt.NumericDate(time.Now().Add(ttl[1]).Unix())
	refresh, err := jwtis.JWTSignedAndEncrypted(privKeys.Enc, privKeys.Sig, claims)
	if err != nil {
		return nil, fmt.Errorf("error in NewJWT create refresh token: %s", err.Error())
	}
	res := &JWTPair{
		AuthToken:    auth,
		RefreshToken: refresh,
	}
	return res, nil
}
