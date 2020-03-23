package grpc

import (
	"context"
	"encoding/json"

	// "errors"

	endpoint "github.com/go-kit/kit/endpoint"
	grpc1 "github.com/go-kit/kit/transport/grpc"
	"github.com/karantin2020/jwtis"
	endpoint1 "github.com/karantin2020/jwtis/pkg/endpoint"
	pb "github.com/karantin2020/jwtis/pkg/grpc/pb"
	service "github.com/karantin2020/jwtis/pkg/service"
	grpc "google.golang.org/grpc"
	jwt "gopkg.in/square/go-jose.v2/jwt"

	errors "github.com/luno/jettison/errors"
)

// New returns an AddService backed by a gRPC server at the other end
//  of the conn. The caller is responsible for constructing the conn, and
// eventually closing the underlying transport. We bake-in certain middlewares,
// implementing the client library pattern.
func New(conn *grpc.ClientConn, options map[string][]grpc1.ClientOption) (service.JWTISService, error) {
	if options == nil {
		options = defOptions
	}
	for k, v := range defOptions {
		if vo, ok := options[k]; !ok || vo == nil {
			options[k] = v
		}
	}
	var newJWTEndpoint endpoint.Endpoint
	{
		newJWTEndpoint = grpc1.NewClient(conn, "pb.JWTISService", "NewJWT", encodeNewJWTRequest, decodeNewJWTResponse, pb.NewJWTReply{}, options["NewJWT"]...).Endpoint()
	}

	var renewJWTEndpoint endpoint.Endpoint
	{
		renewJWTEndpoint = grpc1.NewClient(conn, "pb.JWTISService", "RenewJWT", encodeRenewJWTRequest, decodeRenewJWTResponse, pb.RenewJWTReply{}, options["RenewJWT"]...).Endpoint()
	}

	var revokeJWTEndpoint endpoint.Endpoint
	{
		revokeJWTEndpoint = grpc1.NewClient(conn, "pb.JWTISService", "RevokeJWT", encodeRevokeJWTRequest, decodeRevokeJWTResponse, pb.RevokeJWTReply{}, options["RevokeJWT"]...).Endpoint()
	}

	var authEndpoint endpoint.Endpoint
	{
		authEndpoint = grpc1.NewClient(conn, "pb.JWTISService", "Auth", encodeAuthRequest, decodeAuthResponse, pb.AuthReply{}, options["Auth"]...).Endpoint()
	}

	var registerEndpoint endpoint.Endpoint
	{
		registerEndpoint = grpc1.NewClient(conn, "pb.JWTISService", "Register", encodeRegisterRequest, decodeRegisterResponse, pb.RegisterReply{}, options["Register"]...).Endpoint()
	}

	var updateKeysEndpoint endpoint.Endpoint
	{
		updateKeysEndpoint = grpc1.NewClient(conn, "pb.JWTISService", "UpdateKeys", encodeUpdateKeysRequest, decodeUpdateKeysResponse, pb.UpdateKeysReply{}, options["UpdateKeys"]...).Endpoint()
	}

	var listKeysEndpoint endpoint.Endpoint
	{
		listKeysEndpoint = grpc1.NewClient(conn, "pb.JWTISService", "ListKeys", encodeListKeysRequest, decodeListKeysResponse, pb.ListKeysReply{}, options["ListKeys"]...).Endpoint()
	}

	var delKeysEndpoint endpoint.Endpoint
	{
		delKeysEndpoint = grpc1.NewClient(conn, "pb.JWTISService", "DelKeys", encodeDelKeysRequest, decodeDelKeysResponse, pb.DelKeysReply{}, options["DelKeys"]...).Endpoint()
	}

	var publicKeysEndpoint endpoint.Endpoint
	{
		publicKeysEndpoint = grpc1.NewClient(conn, "pb.JWTISService", "PublicKeys", encodePublicKeysRequest, decodePublicKeysResponse, pb.PublicKeysReply{}, options["PublicKeys"]...).Endpoint()
	}

	return endpoint1.Endpoints{
		AuthEndpoint:       authEndpoint,
		DelKeysEndpoint:    delKeysEndpoint,
		ListKeysEndpoint:   listKeysEndpoint,
		NewJWTEndpoint:     newJWTEndpoint,
		PublicKeysEndpoint: publicKeysEndpoint,
		RegisterEndpoint:   registerEndpoint,
		RenewJWTEndpoint:   renewJWTEndpoint,
		RevokeJWTEndpoint:  revokeJWTEndpoint,
		UpdateKeysEndpoint: updateKeysEndpoint,
	}, nil
}

// encodeNewJWTRequest is a transport/grpc.EncodeRequestFunc that converts a
//  user-domain NewJWT request to a gRPC request.
func encodeNewJWTRequest(_ context.Context, request interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Encoder is not impelemented")
}

// decodeNewJWTResponse is a transport/grpc.DecodeResponseFunc that converts
// a gRPC concat reply to a user-domain concat response.
func decodeNewJWTResponse(_ context.Context, reply interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Decoder is not impelemented")
}

// encodeRenewJWTRequest is a transport/grpc.EncodeRequestFunc that converts a
//  user-domain RenewJWT request to a gRPC request.
func encodeRenewJWTRequest(_ context.Context, request interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Encoder is not impelemented")
}

// decodeRenewJWTResponse is a transport/grpc.DecodeResponseFunc that converts
// a gRPC concat reply to a user-domain concat response.
func decodeRenewJWTResponse(_ context.Context, reply interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Decoder is not impelemented")
}

// encodeRevokeJWTRequest is a transport/grpc.EncodeRequestFunc that converts a
//  user-domain RevokeJWT request to a gRPC request.
func encodeRevokeJWTRequest(_ context.Context, request interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Encoder is not impelemented")
}

// decodeRevokeJWTResponse is a transport/grpc.DecodeResponseFunc that converts
// a gRPC concat reply to a user-domain concat response.
func decodeRevokeJWTResponse(_ context.Context, reply interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Decoder is not impelemented")
}

// encodeAuthRequest is a transport/grpc.EncodeRequestFunc that converts a
//  user-domain Auth request to a gRPC request.
func encodeAuthRequest(_ context.Context, request interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Encoder is not impelemented")
}

// decodeAuthResponse is a transport/grpc.DecodeResponseFunc that converts
// a gRPC concat reply to a user-domain concat response.
func decodeAuthResponse(_ context.Context, reply interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Decoder is not impelemented")
}

// encodeRegisterRequest is a transport/grpc.EncodeRequestFunc that converts a
//  user-domain Register request to a gRPC request.
func encodeRegisterRequest(_ context.Context, request interface{}) (interface{}, error) {
	req := request.(*endpoint1.RegisterRequest)
	return &pb.RegisterRequest{
		KID:             req.KID,
		Expiry:          int64(req.Opts.Expiry),
		SigAlg:          req.Opts.SigAlg,
		SigBits:         int32(req.Opts.SigBits),
		EncAlg:          req.Opts.EncAlg,
		EncBits:         int32(req.Opts.EncBits),
		AuthTTL:         int64(req.Opts.AuthTTL),
		RefreshTTL:      int64(req.Opts.RefreshTTL),
		RefreshStrategy: req.Opts.RefreshStrategy,
	}, nil
}

// decodeRegisterResponse is a transport/grpc.DecodeResponseFunc that converts
// a gRPC concat reply to a user-domain concat response.
func decodeRegisterResponse(_ context.Context, reply interface{}) (interface{}, error) {
	rsp := reply.(*pb.RegisterReply)
	resp := &endpoint1.RegisterResponse{
		KID: rsp.KID,
		Keys: &jwtis.SigEncKeys{
			Expiry:          jwt.NumericDate(rsp.Expiry),
			Valid:           rsp.Valid,
			RefreshStrategy: rsp.RefreshStrategy,
		},
	}
	err := json.Unmarshal(rsp.PubSigKey, &resp.Keys.Sig)
	if err != nil {
		return nil, errors.Wrap(err, "error unmarshal publicSigKey")
	}
	err = json.Unmarshal(rsp.PubEncKey, &resp.Keys.Enc)
	if err != nil {
		return nil, errors.Wrap(err, "error unmarshal publicEncKey")
	}
	return resp, nil
}

// encodeUpdateKeysRequest is a transport/grpc.EncodeRequestFunc that converts a
//  user-domain UpdateKeys request to a gRPC request.
func encodeUpdateKeysRequest(_ context.Context, request interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Encoder is not impelemented")
}

// decodeUpdateKeysResponse is a transport/grpc.DecodeResponseFunc that converts
// a gRPC concat reply to a user-domain concat response.
func decodeUpdateKeysResponse(_ context.Context, reply interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Decoder is not impelemented")
}

// encodeListKeysRequest is a transport/grpc.EncodeRequestFunc that converts a
//  user-domain ListKeys request to a gRPC request.
func encodeListKeysRequest(_ context.Context, request interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Encoder is not impelemented")
}

// decodeListKeysResponse is a transport/grpc.DecodeResponseFunc that converts
// a gRPC concat reply to a user-domain concat response.
func decodeListKeysResponse(_ context.Context, reply interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Decoder is not impelemented")
}

// encodeDelKeysRequest is a transport/grpc.EncodeRequestFunc that converts a
//  user-domain DelKeys request to a gRPC request.
func encodeDelKeysRequest(_ context.Context, request interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Encoder is not impelemented")
}

// decodeDelKeysResponse is a transport/grpc.DecodeResponseFunc that converts
// a gRPC concat reply to a user-domain concat response.
func decodeDelKeysResponse(_ context.Context, reply interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Decoder is not impelemented")
}

// encodePublicKeysRequest is a transport/grpc.EncodeRequestFunc that converts a
//  user-domain PublicKeys request to a gRPC request.
func encodePublicKeysRequest(_ context.Context, request interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Encoder is not impelemented")
}

// decodePublicKeysResponse is a transport/grpc.DecodeResponseFunc that converts
// a gRPC concat reply to a user-domain concat response.
func decodePublicKeysResponse(_ context.Context, reply interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Decoder is not impelemented")
}

var defOptions = map[string][]grpc1.ClientOption{
	"NewJWT":     []grpc1.ClientOption{},
	"RenewJWT":   []grpc1.ClientOption{},
	"RevokeJWT":  []grpc1.ClientOption{},
	"Auth":       []grpc1.ClientOption{},
	"Register":   []grpc1.ClientOption{},
	"UpdateKeys": []grpc1.ClientOption{},
	"ListKeys":   []grpc1.ClientOption{},
	"DelKeys":    []grpc1.ClientOption{},
	"PublicKeys": []grpc1.ClientOption{},
}
