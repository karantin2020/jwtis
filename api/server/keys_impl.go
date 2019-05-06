package serverpb

import (
	"context"

	pb "github.com/karantin2020/jwtis/api/pb"
)

// Register method
func (j *JWTISServer) Register(context.Context, *pb.RegisterClientRequest) (*pb.RegisterClientResponse, error) {
	return nil, nil
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
func (j *JWTISServer) PublicKeys(context.Context, *pb.PubKeysRequest) (*pb.PubKeysResponse, error) {
	return nil, nil
}
