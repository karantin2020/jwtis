package grpc

import (
	grpc "github.com/go-kit/kit/transport/grpc"
	endpoint "github.com/karantin2020/jwtis/pkg/endpoint"
	pb "github.com/karantin2020/jwtis/pkg/grpc/pb"
)

// NewGRPCServer makes a set of endpoints available as a gRPC AddServer
type grpcServer struct {
	newJWT     grpc.Handler
	renewJWT   grpc.Handler
	revokeJWT  grpc.Handler
	auth       grpc.Handler
	register   grpc.Handler
	updateKeys grpc.Handler
	listKeys   grpc.Handler
	delKeys    grpc.Handler
	publicKeys grpc.Handler
}

// NewGRPCServer constructs new grpc server
func NewGRPCServer(endpoints endpoint.Endpoints, options map[string][]grpc.ServerOption) pb.JWTISServiceServer {
	return &grpcServer{
		auth:       makeAuthHandler(endpoints, options["Auth"]),
		delKeys:    makeDelKeysHandler(endpoints, options["DelKeys"]),
		listKeys:   makeListKeysHandler(endpoints, options["ListKeys"]),
		newJWT:     makeNewJWTHandler(endpoints, options["NewJWT"]),
		publicKeys: makePublicKeysHandler(endpoints, options["PublicKeys"]),
		register:   makeRegisterHandler(endpoints, options["Register"]),
		renewJWT:   makeRenewJWTHandler(endpoints, options["RenewJWT"]),
		revokeJWT:  makeRevokeJWTHandler(endpoints, options["RevokeJWT"]),
		updateKeys: makeUpdateKeysHandler(endpoints, options["UpdateKeys"]),
	}
}
