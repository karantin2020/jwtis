package server

import (
	"context"

	errpb "github.com/karantin2020/errorpb"
	pb "github.com/karantin2020/jwtis/api/pb"
	"github.com/karantin2020/jwtis/services/jwtservice"
	"google.golang.org/grpc/codes"
)

// Auth takes in AppToken jwt (bundled into the binary) and returns a AuthToken jwt,
// useable for authentication
func (j *JWTISServer) Auth(ctx context.Context,
	req *pb.AuthRequest) (*pb.AuthReply, error) {
	log.Info().Msgf("jwtis server: requested auth func for kid: '%s'", req.Kid)
	authJWT, err := j.jhg.AuthJWT(req.Kid)
	if err != nil {
		if err == jwtservice.ErrKIDNotExists {
			log.Error().Err(err).Msgf("error creating auth JWT for kid '%s': keys not exist", req.Kid)
			return nil, errpb.New(codes.NotFound,
				"keys not found",
				"jwt service error, couldn't create auth jwt, not found keys; err: "+
					err.Error())
		}
		log.Error().Err(err).Msgf("error creating auth JWT for kid '%s'", req.Kid)
		return nil, errpb.New(codes.Internal,
			"internal server error",
			"jwt service error, couldn't create auth tokens; err: "+err.Error())
	}
	log.Info().Msgf("jwtis server: in auth handler auth JWT generated for kid: '%s'", req.Kid)
	return &pb.AuthReply{
		AuthJWT: authJWT,
	}, nil
}
