package grpc

import (
	"context"
	"encoding/json"
	"time"

	// "errors"

	grpc "github.com/go-kit/kit/transport/grpc"
	endpoint "github.com/karantin2020/jwtis/pkg/endpoint"
	pb "github.com/karantin2020/jwtis/pkg/grpc/pb"
	context1 "golang.org/x/net/context"

	errors "github.com/luno/jettison/errors"
	"github.com/luno/jettison/j"

	service "github.com/karantin2020/jwtis/pkg/service"
)

var (
	// ErrUnimplementedEncDecCode code
	ErrUnimplementedEncDecCode = j.C("ErrUnimplementedEncDec")
	// ErrUnimplementedEncDec error
	ErrUnimplementedEncDec = errors.New("unimplemented encoder/decoder func")
	// InvalidClaimsCode error code
	InvalidClaimsCode = j.C("invalid claims")
	// InvalidKIDCode error code
	InvalidKIDCode = j.C("invalid kid")
	// ErrUnmarshalRequestCode error code
	ErrUnmarshalRequestCode = j.C("error unmarshal request")
	// ErrMarshalRequestCode error code
	ErrMarshalRequestCode = j.C("error marshal request")
	// UnimplementedCode error code
	UnimplementedCode = j.C("unimplemented method")
	// ErrUnimplementedMethod error
	ErrUnimplementedMethod = errors.New("unimplemented method", UnimplementedCode)
)

// makeNewJWTHandler creates the handler logic
func makeNewJWTHandler(endpoints endpoint.Endpoints, options []grpc.ServerOption) grpc.Handler {
	return grpc.NewServer(endpoints.NewJWTEndpoint, decodeNewJWTRequest, encodeNewJWTResponse, options...)
}

// decodeNewJWTResponse is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain NewJWT request
func decodeNewJWTRequest(_ context.Context, r interface{}) (interface{}, error) {
	req := r.(*pb.NewJWTRequest)
	if len(req.KID) < 3 {
		return nil, errors.New("error in NewJWTRequest", InvalidKIDCode)
	}
	if len(req.Claims) < 5 {
		return nil, errors.New("error in NewJWTRequest", InvalidClaimsCode)
	}
	claims := make(map[string]interface{})
	err := json.Unmarshal(req.Claims, &claims)
	return &endpoint.NewJWTRequest{
		KID:    req.KID,
		Claims: claims,
	}, errors.Wrap(err, "error Unmarshal NewJWTRequest claims", ErrUnmarshalRequestCode)
}

// encodeNewJWTResponse is a transport/grpc.EncodeResponseFunc that converts
// a user-domain response to a gRPC reply
func encodeNewJWTResponse(_ context.Context, r interface{}) (interface{}, error) {
	resp := r.(*endpoint.NewJWTResponse)
	return &pb.NewJWTReply{
		ID:           resp.Pair.ID,
		AccessToken:  resp.Pair.AccessToken,
		RefreshToken: resp.Pair.RefreshToken,
		Expiry:       int64(resp.Pair.Expiry),
	}, resp.Err
}
func (g *grpcServer) NewJWT(ctx context1.Context, req *pb.NewJWTRequest) (*pb.NewJWTReply, error) {
	_, rep, err := g.newJWT.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	return rep.(*pb.NewJWTReply), nil
}

// makeRenewJWTHandler creates the handler logic
func makeRenewJWTHandler(endpoints endpoint.Endpoints, options []grpc.ServerOption) grpc.Handler {
	return grpc.NewServer(endpoints.RenewJWTEndpoint, decodeRenewJWTRequest, encodeRenewJWTResponse, options...)
}

// decodeRenewJWTResponse is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain RenewJWT request.
// TODO implement the decoder
func decodeRenewJWTRequest(_ context.Context, r interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Decoder is not implemented")
}

// encodeRenewJWTResponse is a transport/grpc.EncodeResponseFunc that converts
// a user-domain response to a gRPC reply.
// TODO implement the encoder
func encodeRenewJWTResponse(_ context.Context, r interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Encoder is not implemented")
}
func (g *grpcServer) RenewJWT(ctx context1.Context, req *pb.RenewJWTRequest) (*pb.RenewJWTReply, error) {
	_, rep, err := g.renewJWT.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	return rep.(*pb.RenewJWTReply), nil
}

// makeRevokeJWTHandler creates the handler logic
func makeRevokeJWTHandler(endpoints endpoint.Endpoints, options []grpc.ServerOption) grpc.Handler {
	return grpc.NewServer(endpoints.RevokeJWTEndpoint, decodeRevokeJWTRequest, encodeRevokeJWTResponse, options...)
}

// decodeRevokeJWTResponse is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain RevokeJWT request.
// TODO implement the decoder
func decodeRevokeJWTRequest(_ context.Context, r interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Decoder is not implemented")
}

// encodeRevokeJWTResponse is a transport/grpc.EncodeResponseFunc that converts
// a user-domain response to a gRPC reply.
// TODO implement the encoder
func encodeRevokeJWTResponse(_ context.Context, r interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Encoder is not implemented")
}
func (g *grpcServer) RevokeJWT(ctx context1.Context, req *pb.RevokeJWTRequest) (*pb.RevokeJWTReply, error) {
	_, rep, err := g.revokeJWT.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	return rep.(*pb.RevokeJWTReply), nil
}

// makeAuthHandler creates the handler logic
func makeAuthHandler(endpoints endpoint.Endpoints, options []grpc.ServerOption) grpc.Handler {
	return grpc.NewServer(endpoints.AuthEndpoint, decodeAuthRequest, encodeAuthResponse, options...)
}

// decodeAuthResponse is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain Auth request.
// TODO implement the decoder
func decodeAuthRequest(_ context.Context, r interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Decoder is not implemented")
}

// encodeAuthResponse is a transport/grpc.EncodeResponseFunc that converts
// a user-domain response to a gRPC reply.
// TODO implement the encoder
func encodeAuthResponse(_ context.Context, r interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Encoder is not implemented")
}
func (g *grpcServer) Auth(ctx context1.Context, req *pb.AuthRequest) (*pb.AuthReply, error) {
	_, rep, err := g.auth.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	return rep.(*pb.AuthReply), nil
}

// makeRegisterHandler creates the handler logic
func makeRegisterHandler(endpoints endpoint.Endpoints, options []grpc.ServerOption) grpc.Handler {
	return grpc.NewServer(endpoints.RegisterEndpoint, decodeRegisterRequest, encodeRegisterResponse, options...)
}

// decodeRegisterResponse is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain Register request
func decodeRegisterRequest(_ context.Context, r interface{}) (interface{}, error) {
	req := r.(*pb.RegisterRequest)
	opts := &service.KeysOptions{
		SigAlg:          req.SigAlg,
		SigBits:         int(req.SigBits),
		EncAlg:          req.EncAlg,
		EncBits:         int(req.EncBits),
		Expiry:          time.Duration(req.Expiry),
		AuthTTL:         time.Duration(req.AuthTTL),
		RefreshTTL:      time.Duration(req.RefreshTTL),
		RefreshStrategy: req.RefreshStrategy,
	}
	return &endpoint.RegisterRequest{
		KID:  req.KID,
		Opts: opts,
	}, nil
}

// encodeRegisterResponse is a transport/grpc.EncodeResponseFunc that converts
// a user-domain response to a gRPC reply.
// TODO implement the encoder
func encodeRegisterResponse(_ context.Context, r interface{}) (interface{}, error) {
	resp := r.(*endpoint.RegisterResponse)
	pubSig, err := json.Marshal(resp.Keys.Sig)
	if err != nil {
		return nil, errors.Wrap(err, "error marshal Sig key", service.ErrInternalCode)
	}
	pubEnc, err := json.Marshal(resp.Keys.Enc)
	if err != nil {
		return nil, errors.Wrap(err, "error marshal Enc key", service.ErrInternalCode)
	}
	return &pb.RegisterReply{
		KID: resp.KID,
		// AuthJWT:   authJWT,
		PubSigKey:       pubSig,
		PubEncKey:       pubEnc,
		Expiry:          int64(resp.Keys.Expiry),
		Valid:           resp.Keys.Valid,
		RefreshStrategy: resp.Keys.RefreshStrategy,
	}, nil
}
func (g *grpcServer) Register(ctx context1.Context, req *pb.RegisterRequest) (*pb.RegisterReply, error) {
	_, rep, err := g.register.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	return rep.(*pb.RegisterReply), nil
}

// makeUpdateKeysHandler creates the handler logic
func makeUpdateKeysHandler(endpoints endpoint.Endpoints, options []grpc.ServerOption) grpc.Handler {
	return grpc.NewServer(endpoints.UpdateKeysEndpoint, decodeUpdateKeysRequest, encodeUpdateKeysResponse, options...)
}

// decodeUpdateKeysResponse is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain UpdateKeys request.
// TODO implement the decoder
func decodeUpdateKeysRequest(_ context.Context, r interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Decoder is not implemented")
}

// encodeUpdateKeysResponse is a transport/grpc.EncodeResponseFunc that converts
// a user-domain response to a gRPC reply.
// TODO implement the encoder
func encodeUpdateKeysResponse(_ context.Context, r interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Encoder is not implemented")
}
func (g *grpcServer) UpdateKeys(ctx context1.Context, req *pb.UpdateKeysRequest) (*pb.UpdateKeysReply, error) {
	_, rep, err := g.updateKeys.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	return rep.(*pb.UpdateKeysReply), nil
}

// makeListKeysHandler creates the handler logic
func makeListKeysHandler(endpoints endpoint.Endpoints, options []grpc.ServerOption) grpc.Handler {
	return grpc.NewServer(endpoints.ListKeysEndpoint, decodeListKeysRequest, encodeListKeysResponse, options...)
}

// decodeListKeysResponse is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain ListKeys request.
// TODO implement the decoder
func decodeListKeysRequest(_ context.Context, r interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Decoder is not implemented")
}

// encodeListKeysResponse is a transport/grpc.EncodeResponseFunc that converts
// a user-domain response to a gRPC reply.
// TODO implement the encoder
func encodeListKeysResponse(_ context.Context, r interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Encoder is not implemented")
}
func (g *grpcServer) ListKeys(ctx context1.Context, req *pb.ListKeysRequest) (*pb.ListKeysReply, error) {
	_, rep, err := g.listKeys.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	return rep.(*pb.ListKeysReply), nil
}

// makeDelKeysHandler creates the handler logic
func makeDelKeysHandler(endpoints endpoint.Endpoints, options []grpc.ServerOption) grpc.Handler {
	return grpc.NewServer(endpoints.DelKeysEndpoint, decodeDelKeysRequest, encodeDelKeysResponse, options...)
}

// decodeDelKeysResponse is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain DelKeys request.
// TODO implement the decoder
func decodeDelKeysRequest(_ context.Context, r interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Decoder is not implemented")
}

// encodeDelKeysResponse is a transport/grpc.EncodeResponseFunc that converts
// a user-domain response to a gRPC reply.
// TODO implement the encoder
func encodeDelKeysResponse(_ context.Context, r interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Encoder is not implemented")
}
func (g *grpcServer) DelKeys(ctx context1.Context, req *pb.DelKeysRequest) (*pb.DelKeysReply, error) {
	_, rep, err := g.delKeys.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	return rep.(*pb.DelKeysReply), nil
}

// makePublicKeysHandler creates the handler logic
func makePublicKeysHandler(endpoints endpoint.Endpoints, options []grpc.ServerOption) grpc.Handler {
	return grpc.NewServer(endpoints.PublicKeysEndpoint, decodePublicKeysRequest, encodePublicKeysResponse, options...)
}

// decodePublicKeysResponse is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain PublicKeys request.
// TODO implement the decoder
func decodePublicKeysRequest(_ context.Context, r interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Decoder is not implemented")
}

// encodePublicKeysResponse is a transport/grpc.EncodeResponseFunc that converts
// a user-domain response to a gRPC reply.
// TODO implement the encoder
func encodePublicKeysResponse(_ context.Context, r interface{}) (interface{}, error) {
	return nil, errors.New("'JWTIS' Encoder is not implemented")
}
func (g *grpcServer) PublicKeys(ctx context1.Context, req *pb.PublicKeysRequest) (*pb.PublicKeysReply, error) {
	_, rep, err := g.publicKeys.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	return rep.(*pb.PublicKeysReply), nil
}
