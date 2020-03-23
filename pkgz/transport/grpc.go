package transport

import (
	"context"
	"encoding/json"
	"time"

	kitendpoint "github.com/go-kit/kit/endpoint"
	grpctransport "github.com/go-kit/kit/transport/grpc"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"

	grpcerr "github.com/luno/jettison/errors"
	"github.com/luno/jettison/j"

	jwt "gopkg.in/square/go-jose.v2/jwt"

	"github.com/karantin2020/jwtis"
	pb "github.com/karantin2020/jwtis/api/jwtispb"
	"github.com/karantin2020/jwtis/pkg/endpoint"
	"github.com/karantin2020/jwtis/pkg/service"
)

var (
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
	ErrUnimplementedMethod = grpcerr.New("unimplemented method", UnimplementedCode)
)

type grpcServer struct {
	newJWT     grpctransport.Handler
	renewJWT   grpctransport.Handler
	register   grpctransport.Handler
	updateKeys grpctransport.Handler
}

// compile time assertions for grpcserver type implementing pb.JWTISServer
var (
	_ pb.JWTISServer = &grpcServer{}
)

// NewGRPCServer makes a set of endpoints available as a gRPC AddServer.
func NewGRPCServer(name string, jwtEndpoints endpoint.JWTEndpoints,
	keysEndpoints endpoint.KeysEndpoints, zlog zerolog.Logger) pb.JWTISServer {
	options := []grpctransport.ServerOption{
		grpctransport.ServerBefore(RequestID(name)),
		// grpctransport.ServerErrorHandler(
		// 	NewLogErrorHandler(
		// 		zlog.With().Str("package", "transport").
		// 			Str("type", "grpc").Logger(),
		// 	),
		// ),
	}

	return &grpcServer{
		newJWT: grpctransport.NewServer(
			jwtEndpoints.NewJWTEndpoint,
			decodeGRPCNewJWTRequest,
			encodeGRPCNewJWTResponse,
			append(options)...,
		),
		renewJWT: grpctransport.NewServer(
			jwtEndpoints.RenewJWTEndpoint,
			decodeGRPCRenewJWTRequest,
			encodeGRPCRenewJWTResponse,
			append(options)...,
		),
		register: grpctransport.NewServer(
			keysEndpoints.RegisterEndpoint,
			decodeGRPCRegisterRequest,
			encodeGRPCRegisterResponse,
			append(options)...,
		),
		updateKeys: grpctransport.NewServer(
			keysEndpoints.UpdateKeysEndpoint,
			decodeGRPCRegisterRequest,
			encodeGRPCRegisterResponse,
			append(options)...,
		),
	}
}

func (s *grpcServer) NewJWT(ctx context.Context, req *pb.NewTokenRequest) (*pb.TokenResponse, error) {
	_, resp, err := s.newJWT.ServeGRPC(ctx, req)
	return resp.(*pb.TokenResponse), err
}
func (s *grpcServer) RenewJWT(ctx context.Context, req *pb.RenewTokenRequest) (*pb.TokenResponse, error) {
	_, resp, err := s.renewJWT.ServeGRPC(ctx, req)
	return resp.(*pb.TokenResponse), err
}
func (s *grpcServer) RevokeJWT(ctx context.Context, req *pb.RevokeTokenRequest) (*pb.RevokeTokenResponse, error) {
	return nil, ErrUnimplementedMethod
}
func (s *grpcServer) Register(ctx context.Context, req *pb.RegisterClientRequest) (*pb.RegisterClientResponse, error) {
	return nil, ErrUnimplementedMethod
}
func (s *grpcServer) UpdateKeys(ctx context.Context, req *pb.RegisterClientRequest) (*pb.RegisterClientResponse, error) {
	return nil, ErrUnimplementedMethod
}
func (s *grpcServer) DelKeys(ctx context.Context, req *pb.DelKeysRequest) (*pb.DelKeysResponse, error) {
	return nil, ErrUnimplementedMethod
}
func (s *grpcServer) PublicKeys(ctx context.Context, req *pb.PubKeysRequest) (*pb.PubKeysResponse, error) {
	return nil, ErrUnimplementedMethod
}
func (s *grpcServer) ListKeys(ctx context.Context, req *pb.ListKeysRequest) (*pb.ListKeysResponse, error) {
	return nil, ErrUnimplementedMethod
}
func (s *grpcServer) Auth(ctx context.Context, req *pb.AuthRequest) (*pb.AuthReply, error) {
	return nil, ErrUnimplementedMethod
}

// ======== Client ============ //

// NewJWTGRPCClient returns a JWTService backed by a gRPC server at the other end
// of the conn. The caller is responsible for constructing the conn, and
// eventually closing the underlying transport
func NewJWTGRPCClient(conn *grpc.ClientConn, zlog zerolog.Logger) service.JWTService {
	// global client middlewares
	var options []grpctransport.ClientOption

	// Each individual endpoint is an grpc/transport.Client (which implements
	// endpoint.Endpoint) that gets wrapped with various middlewares. If you
	// made your own client library, you'd do this work there, so your server
	// could rely on a consistent set of client behavior.
	var newJWTEndpoint kitendpoint.Endpoint
	{
		newJWTEndpoint = grpctransport.NewClient(
			conn,
			"jwtispb.JWTIS",
			"NewJWT",
			encodeGRPCNewJWTRequest,
			decodeGRPCTokenResponse,
			pb.TokenResponse{},
			options...,
		).Endpoint()
	}
	var renewJWTEndpoint kitendpoint.Endpoint
	{
		renewJWTEndpoint = grpctransport.NewClient(
			conn,
			"jwtispb.JWTIS",
			"NewJWT",
			encodeGRPCRenewJWTRequest,
			decodeGRPCTokenResponse,
			pb.TokenResponse{},
			options...,
		).Endpoint()
	}

	// Returning the endpoint.Set as a service.Service relies on the
	// endpoint.Set implementing the Service methods. That's just a simple bit
	// of glue code.
	return endpoint.JWTEndpoints{
		NewJWTEndpoint:   newJWTEndpoint,
		RenewJWTEndpoint: renewJWTEndpoint,
	}
}

func decodeGRPCNewJWTRequest(_ context.Context, grpcReq interface{}) (request interface{}, err error) {
	req := grpcReq.(*pb.NewTokenRequest)
	if len(req.KID) < 3 {
		return nil, grpcerr.New("error in NewJWTRequest", InvalidKIDCode)
	}
	if len(req.Claims) < 5 {
		return nil, grpcerr.New("error in NewJWTRequest", InvalidClaimsCode)
	}
	var claims = make(map[string]interface{})
	err = json.Unmarshal(req.Claims, &claims)
	return endpoint.NewJWTRequest{
			KID:    req.KID,
			Claims: claims,
		}, grpcerr.Wrap(err, "error Unmarshal NewJWTRequest claims",
			ErrUnmarshalRequestCode, j.KS("kid", req.KID))
}
func encodeGRPCNewJWTResponse(_ context.Context, grpcResp interface{}) (response interface{}, err error) {
	resp := grpcResp.(*service.JWTPair)
	return &pb.TokenResponse{
		ID:           resp.ID,
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		Expiry:       int64(resp.Expiry),
	}, nil
}
func decodeGRPCRenewJWTRequest(_ context.Context, grpcReq interface{}) (request interface{}, err error) {
	req := grpcReq.(*pb.RenewTokenRequest)
	return endpoint.RenewJWTRequest{
		KID:             req.KID,
		RefreshToken:    req.RefreshToken,
		RefreshStrategy: req.RefreshStrategy,
	}, nil
}
func encodeGRPCRenewJWTResponse(_ context.Context, grpcResp interface{}) (response interface{}, err error) {
	resp := grpcResp.(*service.JWTPair)
	return &pb.TokenResponse{
		ID:           resp.ID,
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		Expiry:       int64(resp.Expiry),
	}, nil
}

// encodeGRPCNewJWTRequest is a transport/grpc.EncodeRequestFunc that converts a
// user-domain sum request to a gRPC sum request. Primarily useful in a client.
func encodeGRPCNewJWTRequest(_ context.Context, request interface{}) (interface{}, error) {
	req := request.(endpoint.NewJWTRequest)
	claims, err := json.Marshal(req.Claims)
	return &pb.NewTokenRequest{
			KID:    req.KID,
			Claims: claims,
		}, grpcerr.Wrap(err, "error Marshal NewJWTRequest claims",
			ErrMarshalRequestCode, j.KS("kid", req.KID))
}

// encodeGRPCNewJWTRequest is a transport/grpc.EncodeRequestFunc that converts a
// user-domain sum request to a gRPC sum request. Primarily useful in a client.
func encodeGRPCRenewJWTRequest(_ context.Context, request interface{}) (interface{}, error) {
	req := request.(endpoint.RenewJWTRequest)
	return &pb.RenewTokenRequest{
		KID:             req.KID,
		RefreshToken:    req.RefreshToken,
		RefreshStrategy: req.RefreshStrategy,
	}, nil
}

func decodeGRPCTokenResponse(_ context.Context, grpcResp interface{}) (response interface{}, err error) {
	resp := grpcResp.(*pb.TokenResponse)
	return &service.JWTPair{
		ID:           resp.ID,
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		Expiry:       jwt.NumericDate(resp.Expiry),
	}, nil
}

// ======================== //

func decodeGRPCRegisterRequest(_ context.Context, grpcReq interface{}) (request interface{}, err error) {
	req := grpcReq.(*pb.RegisterClientRequest)
	opts := &jwtis.DefaultOptions{
		SigAlg:          req.SigAlg,
		SigBits:         int(req.SigBits),
		EncAlg:          req.EncAlg,
		EncBits:         int(req.EncBits),
		Expiry:          time.Duration(req.Expiry),
		AuthTTL:         time.Duration(req.AuthTTL),
		RefreshTTL:      time.Duration(req.RefreshTTL),
		RefreshStrategy: req.RefreshStrategy,
	}
	return endpoint.OptsRequest{
		KID:  req.KID,
		Opts: opts,
	}, nil
}
func encodeGRPCRegisterResponse(_ context.Context, grpcResp interface{}) (response interface{}, err error) {
	resp := grpcResp.(*endpoint.OptsResponse)
	pubSig, err := json.Marshal(resp.Opts.Sig)
	if err != nil {
		return nil, grpcerr.Wrap(err, "error marshal Sig key", service.ErrInternalCode)
	}
	pubEnc, err := json.Marshal(resp.Opts.Enc)
	if err != nil {
		return nil, grpcerr.Wrap(err, "error marshal Enc key", service.ErrInternalCode)
	}
	return &pb.RegisterClientResponse{
		KID: resp.KID,
		// AuthJWT:   authJWT,
		PubSigKey: pubSig,
		PubEncKey: pubEnc,
		Expiry:    int64(resp.Opts.Expiry),
		Valid:     resp.Opts.Valid,
	}, nil
}

// // decodeGRPCSumRequest is a transport/grpc.DecodeRequestFunc that converts a
// // gRPC sum request to a user-domain sum request. Primarily useful in a server.
// func decodeGRPCSumRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
// 	req := grpcReq.(*pb.SumRequest)
// 	return addendpoint.SumRequest{A: int(req.A), B: int(req.B)}, nil
// }

// // decodeGRPCConcatRequest is a transport/grpc.DecodeRequestFunc that converts a
// // gRPC concat request to a user-domain concat request. Primarily useful in a
// // server.
// func decodeGRPCConcatRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
// 	req := grpcReq.(*pb.ConcatRequest)
// 	return addendpoint.ConcatRequest{A: req.A, B: req.B}, nil
// }

// // decodeGRPCSumResponse is a transport/grpc.DecodeResponseFunc that converts a
// // gRPC sum reply to a user-domain sum response. Primarily useful in a client.
// func decodeGRPCSumResponse(_ context.Context, grpcReply interface{}) (interface{}, error) {
// 	reply := grpcReply.(*pb.SumReply)
// 	return addendpoint.SumResponse{V: int(reply.V), Err: str2err(reply.Err)}, nil
// }

// // decodeGRPCConcatResponse is a transport/grpc.DecodeResponseFunc that converts
// // a gRPC concat reply to a user-domain concat response. Primarily useful in a
// // client.
// func decodeGRPCConcatResponse(_ context.Context, grpcReply interface{}) (interface{}, error) {
// 	reply := grpcReply.(*pb.ConcatReply)
// 	return addendpoint.ConcatResponse{V: reply.V, Err: str2err(reply.Err)}, nil
// }

// // encodeGRPCSumResponse is a transport/grpc.EncodeResponseFunc that converts a
// // user-domain sum response to a gRPC sum reply. Primarily useful in a server.
// func encodeGRPCSumResponse(_ context.Context, response interface{}) (interface{}, error) {
// 	resp := response.(addendpoint.SumResponse)
// 	return &pb.SumReply{V: int64(resp.V), Err: err2str(resp.Err)}, nil
// }

// // encodeGRPCConcatResponse is a transport/grpc.EncodeResponseFunc that converts
// // a user-domain concat response to a gRPC concat reply. Primarily useful in a
// // server.
// func encodeGRPCConcatResponse(_ context.Context, response interface{}) (interface{}, error) {
// 	resp := response.(addendpoint.ConcatResponse)
// 	return &pb.ConcatReply{V: resp.V, Err: err2str(resp.Err)}, nil
// }

// // encodeGRPCSumRequest is a transport/grpc.EncodeRequestFunc that converts a
// // user-domain sum request to a gRPC sum request. Primarily useful in a client.
// func encodeGRPCSumRequest(_ context.Context, request interface{}) (interface{}, error) {
// 	req := request.(addendpoint.SumRequest)
// 	return &pb.SumRequest{A: int64(req.A), B: int64(req.B)}, nil
// }

// // encodeGRPCConcatRequest is a transport/grpc.EncodeRequestFunc that converts a
// // user-domain concat request to a gRPC concat request. Primarily useful in a
// // client.
// func encodeGRPCConcatRequest(_ context.Context, request interface{}) (interface{}, error) {
// 	req := request.(addendpoint.ConcatRequest)
// 	return &pb.ConcatRequest{A: req.A, B: req.B}, nil
// }

// // These annoying helper functions are required to translate Go error types to
// // and from strings, which is the type we use in our IDLs to represent errors.
// // There is special casing to treat empty strings as nil errors.

// func str2err(s string) error {
// 	if s == "" {
// 		return nil
// 	}
// 	return errors.New(s)
// }

// func err2str(err error) string {
// 	if err == nil {
// 		return ""
// 	}
// 	return err.Error()
// }
