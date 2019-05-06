package serverpb

import (
	"context"
	"encoding/json"

	errpb "github.com/karantin2020/errorpb"
	"google.golang.org/grpc/codes"

	pb "github.com/karantin2020/jwtis/api/pb"
	"github.com/karantin2020/jwtis/services/jwtservice"
	"github.com/karantin2020/jwtis/services/keyservice"
)

// JWTISServer struct holds JWT handlers
type JWTISServer struct {
	khg *keyservice.KeyService
	jhg *jwtservice.JWTService
}

// NewJWTISServer returns new pb.JWTISServer instance
func NewJWTISServer(khg *keyservice.KeyService,
	jhg *jwtservice.JWTService) pb.JWTISServer {
	if khg == nil || jhg == nil {
		panic("NewJWTISServer: passed nil service pointers")
	}
	return &JWTISServer{khg, jhg}
}

// NewJWT is called to issue new jwt token
func (j *JWTISServer) NewJWT(ctx context.Context,
	req *pb.NewTokenRequest) (*pb.TokenResponse, error) {
	claims := make(map[string]interface{})
	if err := json.Unmarshal(req.Claims, &claims); err != nil {
		return nil, errpb.New(codes.InvalidArgument,
			"invalid request data",
			"request body must be valid json and correspond to "+
				"NewTokenRequest{} structure, atleast kid must be provided")
	}

	// Must validate request data

	tokens, err := j.jhg.NewJWT(req.Kid, claims)
	if err != nil {
		if err == jwtservice.ErrKIDNotExists {
			// log.Error().Err(err).Msgf("error creating new JWT for kid '%s': keys not exist", req.Kid)
			return nil, errpb.New(codes.NotFound,
				"keys not found",
				"jwt service error, couldn't create new tokens, not found keys; err: "+
					err.Error())
		}
		// log.Error().Err(err).Msgf("error creating new JWT for kid '%s'", req.Kid)
		return nil, errpb.New(codes.Internal,
			"internal server error",
			"jwt service error, couldn't create new tokens; err: "+err.Error())
	}
	// log.Info().Msgf("new JWT for kid '%s' with id '%s' was created", req.Kid, tokens.ID)
	return &pb.TokenResponse{
		ID:           tokens.ID,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		Expiry:       int64(tokens.Expiry),
	}, nil
}

// RenewJWT is called to refresh jwt token according
// to refresh strategy
func (j *JWTISServer) RenewJWT(ctx context.Context,
	req *pb.RenewTokenRequest) (*pb.TokenResponse, error) {
	return nil, errpb.FromError(nil).Err()
}
