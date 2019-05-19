package server

import (
	"context"
	"encoding/json"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/karantin2020/jwtis"

	errpb "github.com/karantin2020/errorpb"
	pb "github.com/karantin2020/jwtis/api/pb"
	"github.com/karantin2020/jwtis/services/jwtservice"
)

// Register method
func (j *JWTISServer) Register(ctx context.Context,
	req *pb.RegisterClientRequest) (*pb.RegisterClientResponse, error) {
	log.Info().Msgf("jwtis server: requested register func for kid: '%s'", req.Kid)
	var opts = &jwtis.DefaultOptions{
		SigAlg:          req.SigAlg,
		SigBits:         int(req.SigBits),
		EncAlg:          req.EncAlg,
		EncBits:         int(req.EncBits),
		Expiry:          time.Duration(req.Expiry),
		AuthTTL:         time.Duration(req.AuthTTL),
		RefreshTTL:      time.Duration(req.RefreshTTL),
		RefreshStrategy: req.RefreshStrategy,
	}
	pubKeys, err := j.khg.Register(req.Kid, opts)
	if err != nil {
		if err == jwtis.ErrKeysExist {
			log.Error().Err(err).Msgf("error registering new client with kid '%s';"+
				" client with that kid exists", req.Kid)
			return nil, errpb.New(codes.AlreadyExists,
				"key exists",
				"keys service error, couldn't register, key '"+req.Kid+"' exists; err: "+
					err.Error())
		}
		if err == jwtis.ErrKeysExpired || err == jwtis.ErrKeysExistInvalid {
			log.Error().Err(err).Msgf("error registering new client with kid '%s';"+
				" client with that kid exists", req.Kid)
			return nil, errpb.New(codes.ResourceExhausted,
				"keys exist and are expired or invalid",
				"keys service error, couldn't register, exist invalid keys; err: "+
					err.Error())
		}
		log.Error().Err(err).Msg("error registering new client, internal server error")
		return nil, errpb.New(codes.Internal,
			"internal server error",
			"key service error, couldn't create new key; request key status: "+
				err.Error())
	}
	pubSig, err := json.Marshal(pubKeys.Sig)
	if err != nil {
		return nil, errpb.New(codes.Internal,
			"internal server error",
			"key service error, couldn't create new key; request key status: "+
				err.Error())
	}
	pubEnc, err := json.Marshal(pubKeys.Enc)
	if err != nil {
		return nil, errpb.New(codes.Internal,
			"internal server error",
			"key service error, couldn't create new key; request key status: "+
				err.Error())
	}
	authJWT, err := j.jhg.AuthJWT(req.Kid)
	if err != nil {
		if err == jwtservice.ErrKIDNotExists {
			return nil, errpb.New(codes.NotFound,
				"keys not found",
				"jwt service error, couldn't create client token, not found keys; err: "+
					err.Error())
		}
		return nil, errpb.New(codes.Internal,
			"internal server error",
			"jwt service error, couldn't create client token; err: "+err.Error())
	}
	log.Info().Msgf("jwtis server: registered new client with kid '%s',"+
		" not expired and valid", req.Kid)
	return &pb.RegisterClientResponse{
		Kid:       req.Kid,
		AuthJWT:   authJWT,
		PubSigKey: pubSig,
		PubEncKey: pubEnc,
		Expiry:    int64(pubKeys.Expiry),
		Valid:     pubKeys.Valid,
	}, nil
}

// UpdateKeys method
func (j *JWTISServer) UpdateKeys(ctx context.Context,
	req *pb.RegisterClientRequest) (*pb.RegisterClientResponse, error) {
	log.Info().Msgf("jwtis server: requested update keys func for kid: '%s'", req.Kid)
	var opts = &jwtis.DefaultOptions{
		SigAlg:          req.SigAlg,
		SigBits:         int(req.SigBits),
		EncAlg:          req.EncAlg,
		EncBits:         int(req.EncBits),
		Expiry:          time.Duration(req.Expiry),
		AuthTTL:         time.Duration(req.AuthTTL),
		RefreshTTL:      time.Duration(req.RefreshTTL),
		RefreshStrategy: req.RefreshStrategy,
	}
	pubKeys, err := j.khg.UpdateKeys(req.Kid, opts)
	if err != nil {
		if err == jwtis.ErrKeysExpired || err == jwtis.ErrKeysExistInvalid {
			log.Error().Err(err).Msgf("error registering new client with kid '%s';"+
				" client with that kid exists", req.Kid)
			return nil, errpb.New(codes.ResourceExhausted,
				"keys exist and are expired or invalid",
				"keys service error, couldn't update, exist invalid keys; err: "+
					err.Error())
		}
		log.Error().Err(err).Msg("error registering new client, internal server error")
		return nil, errpb.New(codes.Internal,
			"internal server error",
			"key service error, couldn't update key; request key status: "+
				err.Error())
	}
	pubSig, err := json.Marshal(pubKeys.Sig)
	if err != nil {
		return nil, errpb.New(codes.Internal,
			"internal server error",
			"key service error, couldn't update key; request key status: "+
				err.Error())
	}
	pubEnc, err := json.Marshal(pubKeys.Enc)
	if err != nil {
		return nil, errpb.New(codes.Internal,
			"internal server error",
			"key service error, couldn't update key; request key status: "+
				err.Error())
	}
	log.Info().Msgf("jwtis server: updated client with kid '%s',"+
		" not expired and valid", req.Kid)
	return &pb.RegisterClientResponse{
		Kid:       req.Kid,
		AuthJWT:   "",
		PubSigKey: pubSig,
		PubEncKey: pubEnc,
		Expiry:    int64(pubKeys.Expiry),
		Valid:     pubKeys.Valid,
	}, nil
}

// ListKeys returns all registered keys
func (j *JWTISServer) ListKeys(ctx context.Context,
	req *pb.ListKeysRequest) (*pb.ListKeysResponse, error) {
	log.Info().Msg("jwtis server: requested listKeys func, admin role")
	keys, err := j.khg.ListKeys()
	if err != nil {
		return nil, errpb.New(codes.Internal,
			"error list keys",
			"key service error, couldn't marshal keys: "+
				err.Error())
	}
	res := &pb.ListKeysResponse{
		Keys: make([]*pb.KeysInfo, 0, len(keys)),
	}
	for i := range keys {
		res.Keys = append(res.Keys, &pb.KeysInfo{
			Kid:             keys[i].KID,
			Expiry:          keys[i].Expiry,
			AuthTTL:         keys[i].AuthTTL,
			RefreshTTL:      keys[i].RefreshTTL,
			RefreshStrategy: keys[i].RefreshStrategy,
			PubSigKey:       keys[i].Sig,
			PubEncKey:       keys[i].Enc,
			Locked:          keys[i].Locked,
			Valid:           keys[i].Valid,
			Expired:         keys[i].Expired,
		})
	}
	log.Info().Msg("jwtis server: returned list of all keys")
	return res, nil
}

// DelKeys method
func (j *JWTISServer) DelKeys(ctx context.Context,
	req *pb.DelKeysRequest) (*pb.DelKeysResponse, error) {
	log.Info().Msgf("jwtis server: requested delKeys func for kid: '%s'", req.Kid)
	err := j.khg.DelKeys(req.Kid)
	if err != nil {
		if err == jwtis.ErrKeyNotFound {
			return nil, errpb.New(codes.NotFound,
				"error delete key",
				"key service error, couldn't delete key: key wasn't found")
		}
		return nil, errpb.New(codes.Internal,
			"error delete key",
			"key service error, couldn't delete key: "+req.Kid+"; "+
				err.Error())
	}
	log.Info().Msgf("jwtis server: deleted keys for kid: '%s'", req.Kid)
	return &pb.DelKeysResponse{}, nil
}

// PublicKeys method
func (j *JWTISServer) PublicKeys(ctx context.Context,
	req *pb.PubKeysRequest) (*pb.PubKeysResponse, error) {
	log.Info().Msgf("jwtis server: requested publicKeys func for kid: '%s'", req.Kid)
	pubKeys, err := j.khg.PublicKeys(req.Kid)
	if err != nil {
		if err == jwtis.ErrKeysNotFound {
			log.Error().Err(err).Msg("error get public keys, keys not found")
			if err != nil {
				return nil, errpb.New(codes.NotFound,
					"keys not found",
					"key service error, error get public keys: "+
						err.Error())
			}
		}
		if err == jwtis.ErrKeysExpired || err == jwtis.ErrKeysInvalid {
			log.Error().Err(err).Msg("error getting public keys, keys are expired or invalid")
			return nil, errpb.New(codes.ResourceExhausted,
				"keys exist and are expired or invalid",
				"keys service error, error get public keys, exist invalid keys; err: "+
					err.Error())
		}
		log.Error().Err(err).Msg("error getting public keys, internal server error")
		return nil, errpb.New(codes.Internal,
			"internal server error",
			"key service error, error get public keys; request key status: "+
				err.Error())
	}
	pubSig, err := json.Marshal(pubKeys.Sig)
	if err != nil {
		return nil, errpb.New(codes.Internal,
			"internal server error",
			"key service error, couldn't create new key; request key status: "+
				err.Error())
	}
	pubEnc, err := json.Marshal(pubKeys.Enc)
	if err != nil {
		return nil, errpb.New(codes.Internal,
			"internal server error",
			"key service error, couldn't create new key; request key status: "+
				err.Error())
	}
	log.Info().Msgf("jwtis server: sent public keys for kid '%s'", req.Kid)
	return &pb.PubKeysResponse{
		Kid:       req.Kid,
		PubSigKey: pubSig,
		PubEncKey: pubEnc,
	}, nil
}
