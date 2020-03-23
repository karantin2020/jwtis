package service

import (
	"context"
	"fmt"
	"time"

	"github.com/karantin2020/jwtis"
	jwt "gopkg.in/square/go-jose.v2/jwt"

	bluemonday "github.com/microcosm-cc/bluemonday"
	uid "github.com/segmentio/ksuid"
	jose "gopkg.in/square/go-jose.v2"

	errors "github.com/luno/jettison/errors"
	"github.com/luno/jettison/j"
)

// JWTPair holds auth and refresh tokens
type JWTPair struct {
	ID           string          `json:"id"`
	AccessToken  string          `json:"access_token"`            // Short lived auth token
	RefreshToken string          `json:"refresh_token,omitempty"` // Long lived refresh token
	Expiry       jwt.NumericDate `json:"expiry,omitempty"`
}

// KeysOptions represents default sig ang enc options
type KeysOptions struct {
	SigAlg          string        // Algorithm to be used for sign
	SigBits         int           // Key size in bits for sign
	EncAlg          string        // Algorithm to be used for encrypt
	EncBits         int           // Key size in bits for encrypt
	Expiry          time.Duration // Value for keys ttl
	AuthTTL         time.Duration // Value for auth jwt ttl
	RefreshTTL      time.Duration // Value for refresh jwt ttl
	RefreshStrategy string        // optional, values are: 'refreshBoth', 'refreshOnExpire', 'noRefresh' (default)
}

const (
	// StrategyRefreshBoth refresh strategy to issue refresh token on every access token renew
	StrategyRefreshBoth = "refreshBoth"
	// StrategyRefreshOnExpire refresh strategy to issue refresh token if it's expiration time is close
	StrategyRefreshOnExpire = "refreshOnExpire"
	// StrategyNoRefresh refresh strategy means refresh token issue must be explicit, only by calling NewJWT
	StrategyNoRefresh = "noRefresh"
)

// JWTISService implements service logic
type JWTISService interface {
	// NewJWT returns pair of new auth and refresh tokens
	// ttl is a list of auth and refresh tokens valid time
	NewJWT(ctx context.Context, kid string, claims map[string]interface{}) (pair *JWTPair, err error)
	// RenewJWT returns pair of old refresh token and new auth token
	RenewJWT(ctx context.Context, kid, refreshToken, refreshStrategy string) (pair *JWTPair, err error)
	RevokeJWT(ctx context.Context, kid, jwtID, refreshToken string) (err error)
	Auth(ctx context.Context, kid string) (token string, err error)
	Register(ctx context.Context, kid string, opts *KeysOptions) (keys *jwtis.SigEncKeys, err error)
	UpdateKeys(ctx context.Context, kid string, opts *KeysOptions) (keys *jwtis.SigEncKeys, err error)
	ListKeys(ctx context.Context) (keysList []jwtis.KeysInfoSet, err error)
	DelKeys(ctx context.Context, kid string) (err error)
	PublicKeys(ctx context.Context, kid string) (keys *jwtis.SigEncKeys, err error)
}

type basicJWTISService struct {
	keysRepo   *jwtis.KeysRepository
	defContEnc jose.ContentEncryption
}

func (b *basicJWTISService) NewJWT(ctx context.Context, kid string, claims map[string]interface{}) (pair *JWTPair, err error) {
	ok, jwtset, err := b.keysRepo.KeyExists([]byte(kid))
	if err != nil {
		return nil, errors.Wrap(err, "KeyExists error", ErrInternalCode)
	}
	if !ok {
		return nil, errors.Wrap(ErrKIDNotExists, "found no keys", j.KS("kid", kid), ErrKIDNotExistsCode)
	}

	sanitize(claims)

	// define jwt id
	if jti, ok := claims["jti"]; !ok || jti.(string) == "" {
		claimid, err := uid.NewRandom()
		if err != nil {
			return nil, errors.Wrap(err, "error generating new token id", j.KS("cause", "ksuid.NewRandom"), ErrInternalCode)
		}
		claims["jti"] = claimid.String()
	}
	// define jwt issuer
	if iss, ok := claims["iss"]; !ok || iss.(string) == "" {
		claims["iss"] = string(kid)
	}
	// define default expiry times
	ttl := [2]time.Duration{jwtset.AuthTTL, jwtset.RefreshTTL}

	privKeys, err := b.keysRepo.GetPrivateKeys(kid)
	if err != nil {
		return nil, errors.Wrap(err, "GetPrivateKeys error", ErrInternalCode)
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
			return nil, errors.New("error in JWT token exp type assertion", ErrInternalCode)
		}
		if int64(exp) != 0 {
			if time.Now().After(exp.Time()) {
				return nil, errors.New("token (exp field) is expired", j.KV("exp", exp.Time()), ErrInternalCode)
			}
		}
	}
	claims["exp"] = &exp
	auth, err := jwtis.JWTSigned(&privKeys.Sig, claims)
	if err != nil {
		return nil, errors.Wrap(err, "JWTSigned error", ErrInternalCode)
	}
	claims["exp"] = jwt.NewNumericDate(time.Now().Add(ttl[1]))
	refresh, err := jwtis.JWTSignedAndEncrypted(b.defContEnc, &privKeys.Enc, &privKeys.Sig, claims)
	if err != nil {
		return nil, errors.Wrap(err, "error in JWT refresh token", j.KS("cause", "JWTSignedAndEncrypted"), ErrInternalCode)
	}
	res := &JWTPair{
		ID:           claims["jti"].(string),
		AccessToken:  auth,
		RefreshToken: refresh,
		Expiry:       exp,
	}

	return res, nil
}
func (b *basicJWTISService) RenewJWT(ctx context.Context, kid string, refreshToken string, refreshStrategy string) (pair *JWTPair, err error) {
	ok, jwtset, err := b.keysRepo.KeyExists([]byte(kid))
	if err != nil {
		return nil, errors.Wrap(err, "KeyExists error", ErrInternalCode)
	}
	if !ok {
		return nil, ErrKIDNotExists
	}
	pubSig := jwtset.Sig.Public()
	claimsMap := make(map[string]interface{})
	err = jwtis.ClaimsSignedAndEncrypted(&jwtset.Enc, &pubSig, refreshToken, &claimsMap)
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
		return nil, errors.Wrap(err, "JWTSigned error", ErrInternalCode)
	}

	if jwtset.RefreshStrategy == StrategyRefreshBoth || refreshStrategy == StrategyRefreshBoth {
		claimsMap["exp"] = jwt.NewNumericDate(time.Now().Add(ttl[1]))
		refreshToken, err = jwtis.JWTSignedAndEncrypted(b.defContEnc, &jwtset.Enc, &jwtset.Sig, claimsMap)
		if err != nil {
			return nil, errors.Wrap(err, "JWTSignedAndEncrypted error", ErrInternalCode)
		}
	}
	if jwtset.RefreshStrategy == StrategyRefreshOnExpire || refreshStrategy == StrategyRefreshOnExpire {
		if float64(float64(time.Second*time.Duration(int64(nExp)-time.Now().Unix()))/float64(ttl[1])) < 0.3 {
			claimsMap["exp"] = jwt.NewNumericDate(time.Now().Add(ttl[1]))
			refreshToken, err = jwtis.JWTSignedAndEncrypted(b.defContEnc, &jwtset.Enc, &jwtset.Sig, claimsMap)
			if err != nil {
				return nil, errors.Wrap(err, "JWTSignedAndEncrypted error", ErrInternalCode)
			}
		}
	}

	res := &JWTPair{
		ID:           claimsMap["jti"].(string),
		AccessToken:  auth,
		RefreshToken: refreshToken,
		Expiry:       *(claimsMap["exp"].(*jwt.NumericDate)),
	}

	return res, nil
}
func (b *basicJWTISService) RevokeJWT(ctx context.Context, kid string, jwtID string, refreshToken string) (err error) {
	// TODO implement the business logic of RevokeJWT
	return ErrUnimplementedMethod
}
func (b *basicJWTISService) Auth(ctx context.Context, kid string) (token string, err error) {
	ok, _, err := b.keysRepo.KeyExists([]byte(kid))
	if err != nil {
		return "", errors.Wrap(err, "KeyExists error", ErrInternalCode)
	}
	if !ok {
		return "", ErrKIDNotExists
	}

	privKeys, err := b.keysRepo.GetPrivateKeys(kid)
	if err != nil {
		return "", errors.Wrap(err, "GetPrivateKeys error", ErrInternalCode)
	}

	claims := make(map[string]interface{})
	claims["kid"] = kid
	claims["iss"] = "JWTIS"
	authJWT, err := jwtis.JWTSigned(&privKeys.Sig, claims)

	return authJWT, errors.Wrap(err, "JWTSigned error", ErrInternalCode)
}
func (b *basicJWTISService) Register(ctx context.Context, kid string, opts *KeysOptions) (keys *jwtis.SigEncKeys, err error) {
	if b.keysRepo == nil {
		return nil, ErrInvalidKeysRepo
	}
	b.checkOptions(opts)
	resp, err := b.keysRepo.NewKey(kid, convertKeysOptions(opts))
	return resp, errors.Wrap(err, "NewKey error", ErrInternalCode)
}
func (b *basicJWTISService) UpdateKeys(ctx context.Context, kid string, opts *KeysOptions) (keys *jwtis.SigEncKeys, err error) {
	if b.keysRepo == nil {
		return nil, ErrInvalidKeysRepo
	}
	if opts == nil {
		return nil, ErrInvalidOptions
	}
	b.mergeUpdateOptions(kid, opts)
	err = b.keysRepo.DelKey(kid)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't delete key", ErrInternalCode)
	}
	resp, err := b.keysRepo.NewKey(kid, convertKeysOptions(opts))
	return resp, errors.Wrap(err, "NewKey error", ErrInternalCode)
}
func (b *basicJWTISService) ListKeys(ctx context.Context) (keysList []jwtis.KeysInfoSet, err error) {
	if b.keysRepo == nil {
		return nil, ErrInvalidKeysRepo
	}
	resp, err := b.keysRepo.ListKeys()
	return resp, errors.Wrap(err, "ListKeys error", ErrInternalCode)
}
func (b *basicJWTISService) DelKeys(ctx context.Context, kid string) (err error) {
	if b.keysRepo == nil {
		return ErrInvalidKeysRepo
	}
	err = b.keysRepo.DelKey(kid)
	return errors.Wrap(err, "DelKey error", ErrInternalCode)
}
func (b *basicJWTISService) PublicKeys(ctx context.Context, kid string) (keys *jwtis.SigEncKeys, err error) {
	if b.keysRepo == nil {
		return nil, ErrInvalidKeysRepo
	}
	resp, err := b.keysRepo.GetPublicKeys(kid)
	return resp, errors.Wrap(err, "GetPublicKeys error", ErrInternalCode)
}

// NewBasicJWTISService returns a naive, stateless implementation of JWTISService.
func NewBasicJWTISService(keysRepo *jwtis.KeysRepository, contEnc jose.ContentEncryption) JWTISService {
	if keysRepo == nil {
		panic("pointer to jwtis.KeysRepository is nil")
	}
	return &basicJWTISService{
		keysRepo:   keysRepo,
		defContEnc: contEnc,
	}
}

// New returns a JWTISService with all of the expected middleware wired in.
func New(keysrepo *jwtis.KeysRepository, contEnc jose.ContentEncryption, middleware []Middleware) JWTISService {
	var svc JWTISService = NewBasicJWTISService(keysrepo, contEnc)
	for _, m := range middleware {
		svc = m(svc)
	}
	return svc
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

func (b *basicJWTISService) checkOptions(opts *KeysOptions) {
	defs := &b.keysRepo.DefaultOptions
	if opts == nil {
		opts = &KeysOptions{
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

func (b *basicJWTISService) mergeUpdateOptions(kid string, opts *KeysOptions) error {
	if opts == nil {
		return errors.New("error in mergeUpdateOptions; nil opts, nothing to update", ErrInternalCode)
	}
	ok, keysSet, err := b.keysRepo.KeyExists([]byte(kid))
	if err != nil {
		return errors.Wrap(err, "error in mergeUpdateOptions checking key existence", ErrInternalCode)
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
	b.checkOptions(opts)
	return nil
}

func convertKeysOptions(opts *KeysOptions) *jwtis.DefaultOptions {
	return &jwtis.DefaultOptions{
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
