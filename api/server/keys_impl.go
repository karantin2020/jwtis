package serverpb

import (
	"context"
	"encoding/json"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/karantin2020/jwtis"

	errpb "github.com/karantin2020/errorpb"
	pb "github.com/karantin2020/jwtis/api/pb"
)

// Register method
func (j *JWTISServer) Register(ctx context.Context, req *pb.RegisterClientRequest) (*pb.RegisterClientResponse, error) {
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
			log.Error().Err(err).Msgf("error registering new client with kid '%s'; client with that kid exists", req.Kid)
			return nil, errpb.New(codes.AlreadyExists,
				"key exists",
				"keys service error, couldn't register, key exists; err: "+
					err.Error())
		}
		if err == jwtis.ErrKeysExpired || err == jwtis.ErrKeysExistInvalid {
			log.Error().Err(err).Msgf("error registering new client with kid '%s'; client with that kid exists", req.Kid)
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
	log.Info().Msgf("registered new client with kid '%s', not expired and valid", req.Kid)
	return &pb.RegisterClientResponse{
		Kid:         req.Kid,
		ClientToken: "",
		PubSigKey:   pubSig,
		PubEncKey:   pubEnc,
		Expiry:      int64(pubKeys.Expiry),
		Valid:       pubKeys.Valid,
	}, nil
}

// UpdateKeys method
func (j *JWTISServer) UpdateKeys(context.Context, *pb.RegisterClientRequest) (*pb.RegisterClientResponse, error) {
	return nil, nil
}

// DelKeys method
func (j *JWTISServer) DelKeys(context.Context, *pb.DelKeysRequest) (*pb.DelKeysResponse, error) {
	return nil, nil
}

// PublicKeys method
func (j *JWTISServer) PublicKeys(ctx context.Context, req *pb.PubKeysRequest) (*pb.PubKeysResponse, error) {
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
	log.Info().Msgf("get public keys for kid '%s'", req.Kid)
	return &pb.PubKeysResponse{
		Kid:       req.Kid,
		PubSigKey: pubSig,
		PubEncKey: pubEnc,
	}, nil
}