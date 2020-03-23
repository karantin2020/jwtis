package gen

import (
	"context"
	"encoding/json"

	"github.com/go-kit/kit/log"
	"google.golang.org/grpc/codes"

	kitGRPC "github.com/go-kit/kit/transport/grpc"
	pb "github.com/karantin2020/jwtis/svc/pb"

	errors "github.com/pkg/errors"

	cstatus "github.com/cockroachdb/errors/grpc/status"
)

// GRPCServer struct holds gokit handlers
type GRPCServer struct {
	logger                log.Logger
	NewJWTGRPCHandler     kitGRPC.Handler
	RenewJWTGRPCHandler   kitGRPC.Handler
	RevokeJWTGRPCHandler  kitGRPC.Handler
	AuthGRPCHandler       kitGRPC.Handler
	RegisterGRPCHandler   kitGRPC.Handler
	UpdateKeysGRPCHandler kitGRPC.Handler
	ListKeysGRPCHandler   kitGRPC.Handler // TODO : half duplex
	DelKeysGRPCHandler    kitGRPC.Handler
	PublicKeysGRPCHandler kitGRPC.Handler
	PingGRPCHandler       kitGRPC.Handler
	ReadyGRPCHandler      kitGRPC.Handler
}

// NewGRPCServer constructor
func NewGRPCServer(endpoints Endpoints, logger log.Logger, options ...kitGRPC.ServerOption) (*GRPCServer, error) {
	return &GRPCServer{
		logger: logger,

		NewJWTGRPCHandler: kitGRPC.NewServer(
			endpoints.NewJWTEndpoint,
			decodeNewJWTGRPCRequest(),
			encodeNewJWTGRPCResponse(),
			options...,
		),
		RenewJWTGRPCHandler: kitGRPC.NewServer(
			endpoints.RenewJWTEndpoint,
			decodeRenewJWTGRPCRequest(),
			encodeRenewJWTGRPCResponse(),
			options...,
		),
		RevokeJWTGRPCHandler: kitGRPC.NewServer(
			endpoints.RevokeJWTEndpoint,
			decodeRevokeJWTGRPCRequest(),
			encodeRevokeJWTGRPCResponse(),
			options...,
		),
		AuthGRPCHandler: kitGRPC.NewServer(
			endpoints.AuthEndpoint,
			decodeAuthGRPCRequest(),
			encodeAuthGRPCResponse(),
			options...,
		),
		RegisterGRPCHandler: kitGRPC.NewServer(
			endpoints.RegisterEndpoint,
			decodeRegisterGRPCRequest(),
			encodeRegisterGRPCResponse(),
			options...,
		),
		UpdateKeysGRPCHandler: kitGRPC.NewServer(
			endpoints.UpdateKeysEndpoint,
			decodeUpdateKeysGRPCRequest(),
			encodeUpdateKeysGRPCResponse(),
			options...,
		),
		ListKeysGRPCHandler: kitGRPC.NewServer(
			endpoints.ListKeysEndpoint,
			decodeListKeysGRPCStreamRequest(),
			encodeListKeysGRPCStreamResponse(),
			options...,
		),
		DelKeysGRPCHandler: kitGRPC.NewServer(
			endpoints.DelKeysEndpoint,
			decodeDelKeysGRPCRequest(),
			encodeDelKeysGRPCResponse(),
			options...,
		),
		PublicKeysGRPCHandler: kitGRPC.NewServer(
			endpoints.PublicKeysEndpoint,
			decodePublicKeysGRPCRequest(),
			encodePublicKeysGRPCResponse(),
			options...,
		),
		PingGRPCHandler: kitGRPC.NewServer(
			endpoints.PingEndpoint,
			decodePingGRPCRequest(),
			encodePingGRPCResponse(),
			options...,
		),
		ReadyGRPCHandler: kitGRPC.NewServer(
			endpoints.ReadyEndpoint,
			decodeReadyGRPCRequest(),
			encodeReadyGRPCResponse(),
			options...,
		),
	}, nil
}

func decodeNewJWTGRPCRequest() func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		pbReq, ok := req.(*pb.NewJWTRequest)
		if !ok {
			err := errors.Wrapf(ErrNotExpectedGRPCRequestType, "expecting *pb.NewJWTRequest, received %T", req)
			return nil, err
		}
		if len(pbReq.KID) < 3 {
			return nil, errors.Wrapf(ErrInvalidKID, "error in NewJWTRequest, invalid kid: '%s', length %d", pbReq.KID, len(pbReq.KID))
		}
		if pbReq.Claims != nil && len(pbReq.Claims) > 2 && len(pbReq.Claims) < 5 {
			return nil, errors.Wrapf(ErrInvalidClaims, "error in NewJWTRequest, invalid claims: '%s', length %d", pbReq.Claims, len(pbReq.Claims))
		}
		claims := make(map[string]interface{})
		err := json.Unmarshal(pbReq.Claims, &claims)
		if err != nil {
			return nil, errors.Wrap(ErrUnmarshalRequest, "error Unmarshal NewJWTRequest claims: "+err.Error())
		}
		return &NewJWTRequest{
			KID:    pbReq.KID,
			Claims: claims,
		}, nil
	}
}

func encodeNewJWTGRPCResponse() func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, resp interface{}) (interface{}, error) {
		domResp, ok := resp.(*NewJWTResponse)
		if !ok {
			err := errors.Wrapf(ErrNotExpectedGRPCResponseType, "expecting *NewJWTResponse, received %T", resp)
			return nil, err
		}
		return NewPBFromNewJWTResponse(domResp), nil
	}
}

func decodeRenewJWTGRPCRequest() func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		pbReq, ok := req.(*pb.RenewJWTRequest)
		if !ok {
			err := errors.Wrapf(ErrNotExpectedGRPCRequestType, "expecting *pb.RenewJWTRequest, received %T", req)
			return nil, err
		}
		// TODO : validate protobuf
		return NewRenewJWTRequestFromPB(pbReq), nil
	}
}

func encodeRenewJWTGRPCResponse() func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, resp interface{}) (interface{}, error) {
		domResp, ok := resp.(*RenewJWTResponse)
		if !ok {
			err := errors.Wrapf(ErrNotExpectedGRPCResponseType, "expecting *RenewJWTResponse, received %T", resp)
			return nil, err
		}
		return NewPBFromRenewJWTResponse(domResp), nil
	}
}

func decodeRevokeJWTGRPCRequest() func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		pbReq, ok := req.(*pb.RevokeJWTRequest)
		if !ok {
			err := errors.Wrapf(ErrNotExpectedGRPCRequestType, "expecting *pb.RevokeJWTRequest, received %T", req)
			return nil, err
		}
		// TODO : validate protobuf
		return NewRevokeJWTRequestFromPB(pbReq), nil
	}
}

func encodeRevokeJWTGRPCResponse() func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, resp interface{}) (interface{}, error) {
		domResp, ok := resp.(*RevokeJWTResponse)
		if !ok {
			err := errors.Wrapf(ErrNotExpectedGRPCResponseType, "expecting *RevokeJWTResponse, received %T", resp)
			return nil, err
		}
		return NewPBFromRevokeJWTResponse(domResp), nil
	}
}

func decodeAuthGRPCRequest() func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		pbReq, ok := req.(*pb.AuthRequest)
		if !ok {
			err := errors.Wrapf(ErrNotExpectedGRPCRequestType, "expecting *pb.AuthRequest, received %T", req)
			return nil, err
		}
		// TODO : validate protobuf
		return NewAuthRequestFromPB(pbReq), nil
	}
}

func encodeAuthGRPCResponse() func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, resp interface{}) (interface{}, error) {
		domResp, ok := resp.(*AuthResponse)
		if !ok {
			err := errors.Wrapf(ErrNotExpectedGRPCResponseType, "expecting *AuthResponse, received %T", resp)
			return nil, err
		}
		return NewPBFromAuthResponse(domResp), nil
	}
}

func decodeRegisterGRPCRequest() func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		pbReq, ok := req.(*pb.RegisterRequest)
		if !ok {
			err := errors.Wrapf(ErrNotExpectedGRPCRequestType, "expecting *pb.RegisterRequest, received %T", req)
			return nil, err
		}
		// TODO : validate protobuf
		return NewRegisterRequestFromPB(pbReq), nil
	}
}

func encodeRegisterGRPCResponse() func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, resp interface{}) (interface{}, error) {
		msg, ok := resp.(*RegisterResponse)
		if !ok {
			err := errors.Wrapf(ErrNotExpectedGRPCResponseType, "expecting *RegisterResponse, received %T", resp)
			return nil, err
		}
		var result = pb.RegisterResponse{
			KID:     msg.KID,
			AuthJWT: msg.AuthJWT,
		}
		sigKey, err := msg.Keys.Sig.MarshalJSON()
		if err != nil {
			st := cstatus.WrapErr(codes.Internal, "encodeRegisterGRPCResponse: error marshal signing key", err)
			return nil, st
		}
		encKey, err := json.Marshal(msg.Keys.Enc)
		if err != nil {
			return nil, WrapErr(err, codes.Internal, "encodeRegisterGRPCResponse: error marshal encryption key")
		}
		result.PubSigKey = sigKey
		result.PubEncKey = encKey
		result.Expiry = int64(msg.Keys.Expiry)
		result.Valid = msg.Keys.Valid
		result.RefreshStrategy = msg.Keys.RefreshStrategy
		return &result, nil
	}
}

func decodeUpdateKeysGRPCRequest() func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		pbReq, ok := req.(*pb.UpdateKeysRequest)
		if !ok {
			err := errors.Wrapf(ErrNotExpectedGRPCRequestType, "expecting *pb.UpdateKeysRequest, received %T", req)
			return nil, err
		}
		// TODO : validate protobuf
		return NewUpdateKeysRequestFromPB(pbReq), nil
	}
}

func encodeUpdateKeysGRPCResponse() func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, resp interface{}) (interface{}, error) {
		msg, ok := resp.(*UpdateKeysResponse)
		if !ok {
			err := errors.Wrapf(ErrNotExpectedGRPCResponseType, "expecting *UpdateKeysResponse, received %T", resp)
			return nil, err
		}
		var result = pb.UpdateKeysResponse{
			KID:     msg.KID,
			AuthJWT: msg.AuthJWT,
		}
		sigKey, err := json.Marshal(msg.Keys.Sig)
		if err != nil {
			return nil, errors.Wrap(err, "encodeUpdateKeysGRPCResponse: error marshal signing key")
		}
		encKey, err := json.Marshal(msg.Keys.Enc)
		if err != nil {
			return nil, WrapErr(err, codes.Internal, "encodeUpdateKeysGRPCResponse: error marshal encryption key")
		}
		result.PubSigKey = sigKey
		result.PubEncKey = encKey
		result.Expiry = int64(msg.Keys.Expiry)
		result.Valid = msg.Keys.Valid
		result.RefreshStrategy = msg.Keys.RefreshStrategy
		return &result, nil
	}
}

// streaming decoder : nothing to do, just pass it over
// it will be service responsibility to decode
func decodeListKeysGRPCStreamRequest() func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return req, nil
	}
}

// streaming encoder : nothing to do, just pass it over
// it will be service responsibility to encode
func encodeListKeysGRPCStreamResponse() func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, resp interface{}) (interface{}, error) {
		return resp, nil
	}
}

func decodeDelKeysGRPCRequest() func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		pbReq, ok := req.(*pb.DelKeysRequest)
		if !ok {
			err := errors.Wrapf(ErrNotExpectedGRPCRequestType, "expecting *pb.DelKeysRequest, received %T", req)
			return nil, err
		}
		// TODO : validate protobuf
		return NewDelKeysRequestFromPB(pbReq), nil
	}
}

func encodeDelKeysGRPCResponse() func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, resp interface{}) (interface{}, error) {
		domResp, ok := resp.(*DelKeysResponse)
		if !ok {
			err := errors.Wrapf(ErrNotExpectedGRPCResponseType, "expecting *DelKeysResponse, received %T", resp)
			return nil, err
		}
		return NewPBFromDelKeysResponse(domResp), nil
	}
}

func decodePublicKeysGRPCRequest() func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		pbReq, ok := req.(*pb.PublicKeysRequest)
		if !ok {
			err := errors.Wrapf(ErrNotExpectedGRPCRequestType, "expecting *pb.PublicKeysRequest, received %T", req)
			return nil, err
		}
		// TODO : validate protobuf
		return NewPublicKeysRequestFromPB(pbReq), nil
	}
}

func encodePublicKeysGRPCResponse() func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, resp interface{}) (interface{}, error) {
		domResp, ok := resp.(*PublicKeysResponse)
		if !ok {
			err := errors.Wrapf(ErrNotExpectedGRPCResponseType, "expecting *PublicKeysResponse, received %T", resp)
			return nil, err
		}
		sigKey, err := json.Marshal(domResp.Keys.Sig)
		if err != nil {
			return nil, errors.Wrap(err, "error marshal sig key")
		}
		encKey, err := json.Marshal(domResp.Keys.Enc)
		if err != nil {
			return nil, errors.Wrap(err, "error marshal enc key")
		}
		var result = pb.PublicKeysResponse{
			KID:       domResp.KID,
			PubSigKey: sigKey,
			PubEncKey: encKey,
			Expiry:    int64(domResp.Keys.Expiry),
			Valid:     domResp.Keys.Valid,
		}
		// NewPBFromPublicKeysResponse(domResp)
		return &result, nil
	}
}

func decodePingGRPCRequest() func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		pbReq, ok := req.(*pb.PingRequest)
		if !ok {
			err := errors.Wrapf(ErrNotExpectedGRPCRequestType, "expecting *pb.PingRequest, received %T", req)
			return nil, err
		}
		// TODO : validate protobuf
		return NewPingRequestFromPB(pbReq), nil
	}
}

func encodePingGRPCResponse() func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, resp interface{}) (interface{}, error) {
		domResp, ok := resp.(*PingResponse)
		if !ok {
			err := errors.Wrapf(ErrNotExpectedGRPCResponseType, "expecting *PingResponse, received %T", resp)
			return nil, err
		}
		return NewPBFromPingResponse(domResp), nil
	}
}

func decodeReadyGRPCRequest() func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		pbReq, ok := req.(*pb.ReadyRequest)
		if !ok {
			err := errors.Wrapf(ErrNotExpectedGRPCRequestType, "expecting *pb.ReadyRequest, received %T", req)
			return nil, err
		}
		// TODO : validate protobuf
		return NewReadyRequestFromPB(pbReq), nil
	}
}

func encodeReadyGRPCResponse() func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, resp interface{}) (interface{}, error) {
		domResp, ok := resp.(*ReadyResponse)
		if !ok {
			err := errors.Wrapf(ErrNotExpectedGRPCResponseType, "expecting *ReadyResponse, received %T", resp)
			return nil, err
		}
		return NewPBFromReadyResponse(domResp), nil
	}
}

// RequestAndStreamListKeys struct holds request and stream for half duplex
type RequestAndStreamListKeys struct {
	Request *pb.ListKeysRequest
	Stream  pb.JWTISService_ListKeysServer
}

// NewJWT protobuf implementation : no streaming for NewJWT
func (s *GRPCServer) NewJWT(ctx context.Context, req *pb.NewJWTRequest) (*pb.NewJWTResponse, error) {
	_, resp, err := s.NewJWTGRPCHandler.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	pbResp, ok := resp.(*pb.NewJWTResponse)
	if !ok {
		err := errors.Wrapf(ErrNotExpectedProtoGRPCResponseType, "expecting *pb.NewJWTResponse, received %T", resp)
		return nil, err
	}
	return pbResp, nil
}

// RenewJWT protobuf implementation : no streaming for RenewJWT
func (s *GRPCServer) RenewJWT(ctx context.Context, req *pb.RenewJWTRequest) (*pb.RenewJWTResponse, error) {
	_, resp, err := s.RenewJWTGRPCHandler.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	pbResp, ok := resp.(*pb.RenewJWTResponse)
	if !ok {
		err := errors.Wrapf(ErrNotExpectedProtoGRPCResponseType, "expecting *pb.RenewJWTResponse, received %T", resp)
		return nil, err
	}
	return pbResp, nil
}

// RevokeJWT protobuf implementation : no streaming for RevokeJWT
func (s *GRPCServer) RevokeJWT(ctx context.Context, req *pb.RevokeJWTRequest) (*pb.RevokeJWTResponse, error) {
	_, resp, err := s.RevokeJWTGRPCHandler.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	pbResp, ok := resp.(*pb.RevokeJWTResponse)
	if !ok {
		err := errors.Wrapf(ErrNotExpectedProtoGRPCResponseType, "expecting *pb.RevokeJWTResponse, received %T", resp)
		return nil, err
	}
	return pbResp, nil
}

// Auth protobuf implementation : no streaming for Auth
func (s *GRPCServer) Auth(ctx context.Context, req *pb.AuthRequest) (*pb.AuthResponse, error) {
	_, resp, err := s.AuthGRPCHandler.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	pbResp, ok := resp.(*pb.AuthResponse)
	if !ok {
		err := errors.Wrapf(ErrNotExpectedProtoGRPCResponseType, "expecting *pb.AuthResponse, received %T", resp)
		return nil, err
	}
	return pbResp, nil
}

// Register protobuf implementation : no streaming for Register
func (s *GRPCServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	_, resp, err := s.RegisterGRPCHandler.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	pbResp, ok := resp.(*pb.RegisterResponse)
	if !ok {
		err := errors.Wrapf(ErrNotExpectedProtoGRPCResponseType, "expecting *pb.RegisterResponse, received %T", resp)
		return nil, err
	}
	return pbResp, nil
}

// UpdateKeys protobuf implementation : no streaming for UpdateKeys
func (s *GRPCServer) UpdateKeys(ctx context.Context, req *pb.UpdateKeysRequest) (*pb.UpdateKeysResponse, error) {
	_, resp, err := s.UpdateKeysGRPCHandler.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	pbResp, ok := resp.(*pb.UpdateKeysResponse)
	if !ok {
		err := errors.Wrapf(ErrNotExpectedProtoGRPCResponseType, "expecting *pb.UpdateKeysResponse, received %T", resp)
		return nil, err
	}
	return pbResp, nil
}

// ListKeys protobuf implementation : half duplex for ListKeys
func (s *GRPCServer) ListKeys(req *pb.ListKeysRequest, stream pb.JWTISService_ListKeysServer) error {
	reqNStream := &RequestAndStreamListKeys{Request: req, Stream: stream}
	_, _, err := s.ListKeysGRPCHandler.ServeGRPC(stream.Context(), reqNStream)
	return err
}

// DelKeys protobuf implementation : no streaming for DelKeys
func (s *GRPCServer) DelKeys(ctx context.Context, req *pb.DelKeysRequest) (*pb.DelKeysResponse, error) {
	_, resp, err := s.DelKeysGRPCHandler.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	pbResp, ok := resp.(*pb.DelKeysResponse)
	if !ok {
		err := errors.Wrapf(ErrNotExpectedProtoGRPCResponseType, "expecting *pb.DelKeysResponse, received %T", resp)
		return nil, err
	}
	return pbResp, nil
}

// PublicKeys protobuf implementation : no streaming for PublicKeys
func (s *GRPCServer) PublicKeys(ctx context.Context, req *pb.PublicKeysRequest) (*pb.PublicKeysResponse, error) {
	_, resp, err := s.PublicKeysGRPCHandler.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	pbResp, ok := resp.(*pb.PublicKeysResponse)
	if !ok {
		err := errors.Wrapf(ErrNotExpectedProtoGRPCResponseType, "expecting *pb.PublicKeysResponse, received %T", resp)
		return nil, err
	}
	return pbResp, nil
}

// Ping protobuf implementation : no streaming for Ping
func (s *GRPCServer) Ping(ctx context.Context, req *pb.PingRequest) (*pb.PingResponse, error) {
	_, resp, err := s.PingGRPCHandler.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	pbResp, ok := resp.(*pb.PingResponse)
	if !ok {
		err := errors.Wrapf(ErrNotExpectedProtoGRPCResponseType, "expecting *pb.PingResponse, received %T", resp)
		return nil, err
	}
	return pbResp, nil
}

// Ready protobuf implementation : no streaming for Ready
func (s *GRPCServer) Ready(ctx context.Context, req *pb.ReadyRequest) (*pb.ReadyResponse, error) {
	_, resp, err := s.ReadyGRPCHandler.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	pbResp, ok := resp.(*pb.ReadyResponse)
	if !ok {
		err := errors.Wrapf(ErrNotExpectedProtoGRPCResponseType, "expecting *pb.ReadyResponse, received %T", resp)
		return nil, err
	}
	return pbResp, nil
}
