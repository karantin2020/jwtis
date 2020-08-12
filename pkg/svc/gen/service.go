package gen

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/karantin2020/jwtis"
	"github.com/karantin2020/jwtis/pkg/repos/keys"
	pb "github.com/karantin2020/jwtis/pkg/svc/pb"
	errors "github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v2"

	bluemonday "github.com/microcosm-cc/bluemonday"
	uid "github.com/segmentio/ksuid"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

// Status type describes current server status
type Status string

const (
	// Starting server status
	Starting Status = "starting"
	// Ready server status
	Ready Status = "ready"
	// Stalled server status
	Stalled Status = "stalled"
	// Stopped server status
	Stopped Status = "stopped"
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
	Auth(ctx context.Context, req *AuthRequest) (*AuthResponse, error)
	Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error)
	UpdateKeys(ctx context.Context, req *UpdateKeysRequest) (*UpdateKeysResponse, error)
	ListKeys(req *pb.ListKeysRequest, stream pb.JWTISService_ListKeysServer) error // half duplex (client request, server streams)
	DelKeys(ctx context.Context, req *DelKeysRequest) (*DelKeysResponse, error)
	PublicKeys(ctx context.Context, req *PublicKeysRequest) (*PublicKeysResponse, error)
	Ping(ctx context.Context, req *PingRequest) (*PingResponse, error)
	Ready(ctx context.Context, req *ReadyRequest) (*ReadyResponse, error)
	Log() log.Logger
}

// ServerService interface type
type ServerService interface {
	Service
	BroadcastListKeys() chan ListKeysResponse
}

type serviceImpl struct {
	log log.Logger
	// repo              Repository
	broadcastListKeys chan ListKeysResponse // channel to stream to clients

	status Status
	start  jwt.NumericDate

	keysRepo   *keys.Repository
	defContEnc jose.ContentEncryption
}

// NewServerService constructor
func NewServerService(keysrepo *keys.Repository, contEnc jose.ContentEncryption, log log.Logger) ServerService {
	if keysrepo == nil {
		panic(ErrNullKeysRepo)
	}
	return &serviceImpl{
		log: log,
		// repo:              nil,
		broadcastListKeys: make(chan ListKeysResponse),
		status:            Starting,
		start:             jwt.NumericDate(time.Now().Unix()),
		keysRepo:          keysrepo,
		defContEnc:        contEnc,
	}
}

// Log server service method
func (s *serviceImpl) Log() log.Logger {
	return s.log
}

// BroadcastListKeys server service method
// getter for broadcastListKeys chan ListKeysResponse
func (s *serviceImpl) BroadcastListKeys() chan ListKeysResponse {
	return s.broadcastListKeys
}

// NewJWT server service method
func (s *serviceImpl) NewJWT(ctx context.Context, req *NewJWTRequest) (*NewJWTResponse, error) {
	if s.keysRepo == nil {
		return nil, ErrNullKeysRepo
	}
	kid := req.KID
	ok, keysSet, err := s.keysRepo.KeyExists([]byte(kid))
	if err != nil {
		return nil, errors.Wrap(ErrInternal, "NewJWT: check KeyExists error: "+err.Error())
	}
	if !ok {
		return nil, errors.Wrapf(ErrInvalidArgument, "NewJWT: found no keys with kid '%s'", kid)
	}

	sanitize(req.Claims)

	// define jwt id
	if jti, ok := req.Claims["jti"]; !ok || jti.(string) == "" {
		claimid, err := uid.NewRandom()
		if err != nil {
			return nil, errors.Wrap(ErrInternal, "NewJWT: error generating new token id: "+err.Error())
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
		return nil, errors.Wrap(ErrInternal, "NewJWT: GetPrivateKeys error: "+err.Error())
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
			return nil, errors.Wrap(ErrInvalidArgument, "NewJWT: invalid exp type in claims")
		}
		if int64(exp) != 0 {
			if time.Now().After(exp.Time()) {
				return nil, errors.Wrap(ErrInvalidArgument, "NewJWT: token (exp field) is expired")
			}
		}
	}
	req.Claims["exp"] = &exp
	auth, err := jwtis.JWTSigned(&privKeys.Sig, req.Claims)
	if err != nil {
		return nil, errors.Wrap(ErrInternal, "NewJWT: JWTSigned error: "+err.Error())
	}
	req.Claims["exp"] = jwt.NewNumericDate(time.Now().Add(ttl[1]))
	refresh, err := jwtis.JWTSignedAndEncrypted(s.defContEnc, &privKeys.Enc, &privKeys.Sig, req.Claims)
	if err != nil {
		return nil, errors.Wrap(ErrInternal, "NewJWT: JWT refresh error: "+err.Error())
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
		return nil, ErrNullKeysRepo
	}
	kid := req.KID
	refreshToken := req.RefreshToken
	refreshStrategy := req.RefreshStrategy
	ok, keysSet, err := s.keysRepo.KeyExists([]byte(kid))
	if err != nil {
		return nil, errors.Wrap(ErrInternal, "RenewJWT: KeyExists error: "+err.Error())
	}
	if !ok {
		return nil, ErrKIDNotExists
	}
	pubSig := keysSet.Sig.Public()
	claimsMap := make(map[string]interface{})
	err = jwtis.ClaimsSignedAndEncrypted(&keysSet.Enc, &pubSig, refreshToken, &claimsMap)
	if err != nil {
		return nil, ErrDecryptRefreshToken
	}

	var mErr jwtis.Error
	if _, ok := claimsMap["jti"]; !ok {
		mErr.Append(errors.Wrap(ErrInvalidRefreshToken, "RenewJWT: jti field is empty"))
	}
	if _, ok := claimsMap["iss"]; !ok {
		mErr.Append(errors.Wrap(ErrInvalidRefreshToken, "RenewJWT: iss field is empty"))
	}
	if _, ok := claimsMap["iat"]; !ok {
		mErr.Append(errors.Wrap(ErrInvalidRefreshToken, "RenewJWT: iat field is empty"))
	}
	if _, ok := claimsMap["nbf"]; !ok {
		mErr.Append(errors.Wrap(ErrInvalidRefreshToken, "RenewJWT: nbf field is empty"))
	}
	var nExp jwt.NumericDate
	if sExp, ok := claimsMap["exp"]; !ok {
		mErr.Append(errors.Wrap(ErrInvalidRefreshToken, "RenewJWT: exp field is empty"))
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
			mErr.Append(errors.Wrap(ErrInvalidRefreshToken, "RenewJWT: error in renewJWT: token exp type assertion"))
		}
	}
	// exp field must not be negative
	if nExp < 1 {
		mErr.Append(errors.Wrap(ErrInvalidRefreshToken, "RenewJWT: error in renewJWT: zero value of exp claim"))
	}
	if time.Now().After(time.Unix(int64(nExp), 0)) {
		return nil, ErrRefreshTokenExpired
	}
	if len(mErr) != 0 {
		return nil, errors.Wrap(ErrInvalidRefreshClaims, mErr.Error())
	}

	// define default expiry times
	ttl := [2]time.Duration{keysSet.AuthTTL, keysSet.RefreshTTL}

	// [TODO] Validate and verify refresh token
	// Check refresh token expiration
	// create new auth claims

	claimsMap["exp"] = jwt.NewNumericDate(time.Now().Add(ttl[0]))
	auth, err := jwtis.JWTSigned(&keysSet.Sig, claimsMap)
	if err != nil {
		return nil, errors.Wrap(ErrInternal, "RenewJWT: JWTSigned error: "+err.Error())
	}

	if keysSet.RefreshStrategy == StrategyRefreshBoth || refreshStrategy == StrategyRefreshBoth {
		claimsMap["exp"] = jwt.NewNumericDate(time.Now().Add(ttl[1]))
		refreshToken, err = jwtis.JWTSignedAndEncrypted(s.defContEnc, &keysSet.Enc, &keysSet.Sig, claimsMap)
		if err != nil {
			return nil, errors.Wrap(ErrInternal, "RenewJWT: JWTSignedAndEncrypted error "+err.Error())
		}
	}
	if keysSet.RefreshStrategy == StrategyRefreshOnExpire || refreshStrategy == StrategyRefreshOnExpire {
		if float64(float64(time.Second*time.Duration(int64(nExp)-time.Now().Unix()))/float64(ttl[1])) < 0.3 {
			claimsMap["exp"] = jwt.NewNumericDate(time.Now().Add(ttl[1]))
			refreshToken, err = jwtis.JWTSignedAndEncrypted(s.defContEnc, &keysSet.Enc, &keysSet.Sig, claimsMap)
			if err != nil {
				return nil, errors.Wrap(ErrInternal, "RenewJWT: JWTSignedAndEncrypted error "+err.Error())
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
		return nil, ErrNullKeysRepo
	}
	return nil, ErrUnimplemented
}

// Auth server service method
func (s *serviceImpl) Auth(ctx context.Context, req *AuthRequest) (*AuthResponse, error) {
	if s.keysRepo == nil {
		return nil, ErrNullKeysRepo
	}
	kid := req.KID
	ok, kis, err := s.keysRepo.KeyExists([]byte(kid))
	if err != nil {
		return nil, errors.Wrap(ErrInternal, "KeyExists error: "+err.Error())
	}
	if !ok {
		return nil, ErrKIDNotExists
	}

	privKeys, err := s.keysRepo.GetPrivateKeys(kid)
	if err != nil {
		return nil, errors.Wrap(ErrInternal, "GetPrivateKeys error: "+err.Error())
	}

	claims := make(map[string]interface{})
	claims["kid"] = kid
	claims["iss"] = "JWTIS"
	claims["iat"] = jwt.NewNumericDate(time.Now())
	claims["nbf"] = claims["iat"]
	claims["exp"] = kis.Expiry
	authJWT, err := jwtis.JWTSigned(&privKeys.Sig, claims)
	if err != nil {
		return nil, errors.Wrap(ErrInternal, "JWTSigned error: "+err.Error())
	}
	return &AuthResponse{
		AuthJWT: authJWT,
	}, nil
}

// Register server service method
func (s *serviceImpl) Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	if s.keysRepo == nil {
		return nil, ErrNullKeysRepo
	}
	s.checkOptions(req)
	opts := convertKeysOptions(req)
	resp, err := s.keysRepo.NewKey(req.KID, opts)
	if err != nil {
		return nil, errors.Wrap(ErrInternal, "Register: create new keys error: "+err.Error())
	}
	authJWT, err := s.Auth(ctx, &AuthRequest{
		KID: req.KID,
	})
	if err != nil {
		return nil, errors.Wrap(ErrInternal, "Register: generate auth token error: "+err.Error())
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
		return nil, ErrNullKeysRepo
	}
	if req == nil {
		return nil, errors.Wrap(ErrInvalidArgument, "UpdateKeys: UpdateKeysRequest pointer is nil")
	}
	kid := req.KID
	s.mergeUpdateOptions(kid, req)
	err := s.keysRepo.DelKey(kid)
	if err != nil {
		return nil, errors.Wrap(ErrInternal, "UpdateKeys: error delete keys: "+err.Error())
	}
	resp, err := s.keysRepo.NewKey(kid, &keys.DefaultOptions{
		SigAlg:          req.SigAlg,
		SigBits:         req.SigBits,
		EncAlg:          req.EncAlg,
		EncBits:         req.EncBits,
		Expiry:          req.Expiry,
		AuthTTL:         req.AuthTTL,
		RefreshTTL:      req.RefreshTTL,
		RefreshStrategy: req.RefreshStrategy,
	})
	if err != nil {
		return nil, errors.Wrap(ErrInternal, "UpdateKeys: error create new keys: "+err.Error())
	}
	authJWT, err := s.Auth(ctx, &AuthRequest{
		KID: req.KID,
	})
	if err != nil {
		return nil, errors.Wrap(ErrInternal, "UpdateKeys: generate auth token error: "+err.Error())
	}
	return &UpdateKeysResponse{
		KID:     req.KID,
		AuthJWT: authJWT.AuthJWT,
		Keys:    resp,
	}, nil
}

// ListKeys half duple
// ListKeys server service method for ListKeys
func (s *serviceImpl) ListKeys(pbReq *pb.ListKeysRequest, stream pb.JWTISService_ListKeysServer) error {
	if s.keysRepo == nil {
		return ErrNullKeysRepo
	}
	req := NewListKeysRequestFromPB(pbReq)
	resp, err := s.listKeys(stream.Context(), req)
	if err != nil {
		return err
	}
	level.Debug(s.log).Log("server_listKeys_resp_len", strconv.Itoa(len(resp)))
	for _, message := range resp {
		level.Debug(s.log).Log("ListKeysService", "Sending payload")
		sigKey, err := json.Marshal(message.Keys.Sig)
		if err != nil {
			err = errors.Wrap(err, "error marshal Sig key")
			level.Error(s.log).Log("ListKeysService error", err)
		}
		encKey, err := json.Marshal(message.Keys.Enc)
		if err != nil {
			err = errors.Wrap(err, "error marshal Enc key")
			level.Error(s.log).Log("ListKeysService error", err)
		}
		var result = pb.ListKeysResponse{
			KID:             message.KID,
			Expiry:          message.Keys.Expiry,
			AuthTTL:         message.Keys.AuthTTL,
			RefreshTTL:      message.Keys.RefreshTTL,
			RefreshStrategy: message.Keys.RefreshStrategy,
			PubSigKey:       sigKey,
			PubEncKey:       encKey,
			Locked:          message.Keys.Locked,
			Valid:           message.Keys.Valid,
			Expired:         message.Keys.Expired,
		}
		// payload := NewPBFromListKeysResponse(&message)
		// send a message to the client
		if sendErr := stream.Send(&result); sendErr != nil {
			level.Error(s.log).Log("send_error", sendErr)
			return sendErr
		}
	}
	return nil
}

func (s *serviceImpl) listKeys(ctx context.Context, req *ListKeysRequest) ([]ListKeysResponse, error) {
	if s.keysRepo == nil {
		return nil, ErrNullKeysRepo
	}
	resp, err := s.keysRepo.ListKeys()
	if err != nil {
		return nil, errors.Wrap(ErrInternal, "listKeys: error request keys: "+err.Error())
	}
	listResp := make([]ListKeysResponse, len(resp))
	for i := range resp {
		listResp[i] = ListKeysResponse{
			KID:  resp[i].KID,
			Keys: resp[i],
		}
	}
	return listResp, nil
}

// DelKeys server service method
func (s *serviceImpl) DelKeys(ctx context.Context, req *DelKeysRequest) (*DelKeysResponse, error) {
	if s.keysRepo == nil {
		return nil, ErrNullKeysRepo
	}
	err := s.keysRepo.DelKey(req.KID)
	if err != nil {
		return nil, errors.Wrap(ErrInternal, "DelKeys: error delete keys: "+err.Error())
	}
	return &DelKeysResponse{}, nil
}

// PublicKeys server service method
func (s *serviceImpl) PublicKeys(ctx context.Context, req *PublicKeysRequest) (*PublicKeysResponse, error) {
	if s.keysRepo == nil {
		return nil, ErrNullKeysRepo
	}
	resp, err := s.keysRepo.GetPublicKeys(req.KID)
	if err != nil {
		return nil, errors.Wrap(ErrInternal, "PublicKeys: error fetch publick keys: "+err.Error())
	}
	return &PublicKeysResponse{
		KID:  req.KID,
		Keys: resp,
	}, nil
}

// Ping server service method
func (s *serviceImpl) Ping(ctx context.Context, req *PingRequest) (*PingResponse, error) {
	if s.keysRepo == nil {
		return nil, ErrNullKeysRepo
	}
	return &PingResponse{
		Status: string(s.status),
	}, nil
}

// Ready server service method
func (s *serviceImpl) Ready(ctx context.Context, req *ReadyRequest) (*ReadyResponse, error) {
	if s.keysRepo == nil {
		return nil, ErrNullKeysRepo
	}
	return &ReadyResponse{
		Status: string(s.status),
		Start:  s.start,
		Up:     time.Since(s.start.Time()),
	}, nil
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
		return errors.Wrap(ErrInternal, "mergeUpdateOptions: nil opts, nothing to update")
	}
	ok, keysSet, err := s.keysRepo.KeyExists([]byte(kid))
	if err != nil {
		return errors.Wrap(ErrInternal, "mergeUpdateOptions: checking key existence error: "+err.Error())
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
