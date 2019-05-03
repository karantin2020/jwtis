package grpc

import (
	"context"
	"encoding/json"

	"google.golang.org/grpc/codes"

	hsrv "github.com/karantin2020/jwtis/http"
	pb "github.com/karantin2020/jwtis/http/pb"
	"github.com/karantin2020/jwtis/services/jwtservice"
	"github.com/karantin2020/jwtis/services/keyservice"
	"google.golang.org/grpc/metadata"
)

var (
	errMissingMetadata = pb.NewError(codes.InvalidArgument, "missing metadata")
	errInvalidRequest  = pb.NewError(codes.InvalidArgument, "invalid request")
)

type jWTISServer struct {
	khg *keyservice.KeyService
	jhg *jwtservice.JWTService
}

// NewJWTISServer returns new pb.JWTISServer instance
func NewJWTISServer(khg *keyservice.KeyService,
	jhg *jwtservice.JWTService) pb.JWTISServer {
	if khg == nil || jhg == nil {
		panic("NewJWTISServer: passed nil service pointers")
	}
	return &jWTISServer{khg, jhg}
}

func (j *jWTISServer) NewJWT(ctx context.Context,
	req *pb.NewTokenRequest) (*pb.TokenResponse, error) {
	var tr = hsrv.NewTokenRequest{Claims: make(map[string]interface{})}
	if err := json.Unmarshal(req.Claims, &tr.Claims); err != nil {
		return nil, pb.NewError(codes.InvalidArgument,
			"invalid request data",
			"request body must be valid json and correspond to "+
				"NewTokenRequest{} structure, atleast kid must be provided")
	}

	// Must validate request data

	tokens, err := j.jhg.NewJWT(req.Kid, tr.Claims)
	if err != nil {
		if err == jwtservice.ErrKIDNotExists {
			log.Error().Err(err).Msgf("error creating new JWT for kid '%s': keys not exist", req.Kid)
			return nil, pb.NewError(codes.NotFound,
				"keys not found",
				"jwt service error, couldn't create new tokens, not found keys; err: "+
					err.Error())
		}
		log.Error().Err(err).Msgf("error creating new JWT for kid '%s'", req.Kid)
		return nil, pb.NewError(codes.Internal,
			"internal server error",
			"jwt service error, couldn't create new tokens; err: "+err.Error())
	}
	log.Info().Msgf("new JWT for kid '%s' with id '%s' was created", req.Kid, tokens.ID)
	return &pb.TokenResponse{
		ID:           tokens.ID,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		Expiry:       int64(tokens.Expiry),
	}, nil
}

func (j *jWTISServer) RenewJWT(ctx context.Context,
	req *pb.RenewTokenRequest) (*pb.TokenResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errMissingMetadata
	}
	_ = md
	return nil, nil
}
