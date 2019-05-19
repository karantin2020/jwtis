package server

import (
	"context"
	"encoding/json"

	errpb "github.com/karantin2020/errorpb"
	"google.golang.org/grpc/codes"

	pb "github.com/karantin2020/jwtis/api/pb"
	"github.com/karantin2020/jwtis/services/jwtservice"
)

// NewJWT is called to issue new jwt token
func (j *JWTISServer) NewJWT(ctx context.Context,
	req *pb.NewTokenRequest) (*pb.TokenResponse, error) {
	log.Info().Msgf("jwtis server: requested newJWT func for kid: '%s'", req.Kid)
	claims := make(map[string]interface{})
	if req.Claims != "" && req.Claims != "{}" {
		if err := json.Unmarshal([]byte(req.Claims), &claims); err != nil {
			return nil, errpb.New(codes.InvalidArgument,
				"invalid request data",
				"request body must be valid json and correspond to "+
					"NewTokenRequest{} structure, atleast kid must be provided")
		}
	}

	// Must validate request data

	tokens, err := j.jhg.NewJWT(req.Kid, claims)
	if err != nil {
		if err == jwtservice.ErrKIDNotExists {
			log.Error().Err(err).Msgf("error creating new JWT for kid '%s':"+
				" keys not exist", req.Kid)
			return nil, errpb.New(codes.NotFound,
				"keys not found",
				"jwt service error, couldn't create new tokens, not found keys; err: "+
					err.Error())
		}
		log.Error().Err(err).Msgf("error creating new JWT for kid '%s'", req.Kid)
		return nil, errpb.New(codes.Internal,
			"internal server error",
			"jwt service error, couldn't create new tokens; err: "+err.Error())
	}
	log.Info().Msgf("jwtis server: new JWT for kid '%s' with id '%s' was created",
		req.Kid, tokens.ID)
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
	log.Info().Msgf("jwtis server: requested renewJWT func for kid: '%s'", req.Kid)
	tokens, err := j.jhg.RenewJWT(req.Kid, req.RefreshToken,
		req.RefreshStrategy)
	if err != nil {
		switch err {
		case jwtservice.ErrKIDNotExists:
			return nil, errpb.New(codes.NotFound,
				"keys not found",
				"jwt service error, couldn't renew tokens, not found keys; err: "+
					err.Error())
		case jwtservice.ErrDecryptRefreshToken:
			return nil, errpb.New(codes.InvalidArgument,
				"error decrypt token",
				"jwt service error, couldn't renew tokens, error decrypt refresh token; err: "+
					err.Error())
		case jwtservice.ErrRefreshTokenExpired:
			return nil, errpb.New(codes.ResourceExhausted,
				"refresh token expired",
				"jwt service error, couldn't renew tokens, refresh token expired; err: "+
					err.Error())
		case jwtservice.ErrInvalidRefreshClaims:
			return nil, errpb.New(codes.ResourceExhausted,
				"invalid refresh token claims",
				"jwt service error, couldn't renew tokens, refresh token claims are invalid; err: "+
					err.Error())
		default:
			return nil, errpb.New(codes.Internal,
				"error renew token",
				"jwt service error, couldn't renew tokens, internal error; err: "+
					err.Error())
		}
	}
	log.Info().Msgf("jwtis server: new JWT for kid '%s' with id '%s' was created", req.Kid, tokens.ID)
	return &pb.TokenResponse{
		ID:           tokens.ID,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		Expiry:       int64(tokens.Expiry),
	}, nil
}
