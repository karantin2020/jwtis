package keys

import (
	"context"
	"encoding/json"

	"go.uber.org/zap"

	pb "github.com/karantin2020/jwtis/api/keys/v1"

	"github.com/karantin2020/jwtis/pkg/errdef"
	errors "github.com/pkg/errors"
)

type grpcServer struct {
	logger *zap.Logger
	svc    Service
	// pb.UnimplementedKeysServer
}

// NewKeysServer creates new KeysServer instance
func NewKeysServer(service Service, log *zap.Logger) pb.KeysServer {
	return &grpcServer{
		logger: log,
		svc:    service,
	}
}

func decodeAuthGRPCRequest(ctx context.Context, req interface{}) (*AuthRequest, error) {
	pbReq, ok := req.(*pb.AuthRequest)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCRequestType, "expecting *pb.AuthRequest, received %T", req)
		return nil, err
	}
	// TODO : validate protobuf
	return NewAuthRequestFromPB(pbReq), nil
}

func encodeAuthGRPCResponse(ctx context.Context, resp interface{}) (*pb.AuthResponse, error) {
	domResp, ok := resp.(*AuthResponse)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCResponseType, "expecting *AuthResponse, received %T", resp)
		return nil, err
	}
	return NewPBFromAuthResponse(domResp), nil
}

func decodeRegisterGRPCRequest(ctx context.Context, req interface{}) (*RegisterRequest, error) {
	pbReq, ok := req.(*pb.RegisterRequest)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCRequestType, "expecting *pb.RegisterRequest, received %T", req)
		return nil, err
	}
	// TODO : validate protobuf
	return NewRegisterRequestFromPB(pbReq), nil
}

func encodeRegisterGRPCResponse(ctx context.Context, resp interface{}) (*pb.RegisterResponse, error) {
	msg, ok := resp.(*RegisterResponse)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCResponseType, "expecting *RegisterResponse, received %T", resp)
		return nil, err
	}
	var result = pb.RegisterResponse{
		KID:     msg.KID,
		AuthJWT: msg.AuthJWT,
	}
	sigKey, err := msg.Keys.Sig.MarshalJSON()
	if err != nil {
		st := errors.Wrap(errdef.ErrInternal, "encodeRegisterGRPCResponse: error marshal signing key: "+err.Error())
		return nil, st
	}
	encKey, err := json.Marshal(msg.Keys.Enc)
	if err != nil {
		return nil, errors.Wrap(errdef.ErrInternal, "encodeRegisterGRPCResponse: error marshal encryption key")
	}
	result.PubSigKey = sigKey
	result.PubEncKey = encKey
	result.Expiry = int64(msg.Keys.Expiry)
	result.Valid = msg.Keys.Valid
	result.RefreshStrategy = msg.Keys.RefreshStrategy
	return &result, nil
}

func decodeUpdateKeysGRPCRequest(ctx context.Context, req interface{}) (*UpdateKeysRequest, error) {
	pbReq, ok := req.(*pb.UpdateKeysRequest)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCRequestType, "expecting *pb.UpdateKeysRequest, received %T", req)
		return nil, err
	}
	// TODO : validate protobuf
	return NewUpdateKeysRequestFromPB(pbReq), nil
}

func encodeUpdateKeysGRPCResponse(ctx context.Context, resp interface{}) (*pb.UpdateKeysResponse, error) {
	msg, ok := resp.(*UpdateKeysResponse)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCResponseType, "expecting *UpdateKeysResponse, received %T", resp)
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
		return nil, errors.Wrap(errdef.ErrInternal, "encodeUpdateKeysGRPCResponse: error marshal encryption key")
	}
	result.PubSigKey = sigKey
	result.PubEncKey = encKey
	result.Expiry = int64(msg.Keys.Expiry)
	result.Valid = msg.Keys.Valid
	result.RefreshStrategy = msg.Keys.RefreshStrategy
	return &result, nil
}

// streaming decoder : nothing to do, just pass it over
// it will be service responsibility to decode
func decodeListKeysGRPCRequest(ctx context.Context, req interface{}) (*ListKeysRequest, error) {
	pbReq, ok := req.(*pb.ListKeysRequest)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCRequestType, "expecting *pb.ListKeysRequest, received %T", req)
		return nil, err
	}
	// TODO : validate protobuf
	return NewListKeysRequestFromPB(pbReq), nil
}

// streaming encoder : nothing to do, just pass it over
// it will be service responsibility to encode
func encodeListKeysGRPCResponse(ctx context.Context, resp interface{}) (*pb.ListKeysResponse, error) {
	domResp, ok := resp.(*ListKeysResponse)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCResponseType, "expecting *ListKeysResponse, received %T", resp)
		return nil, err
	}
	return NewPBFromListKeysResponse(domResp), nil
}

func decodeDelKeysGRPCRequest(ctx context.Context, req interface{}) (*DelKeysRequest, error) {
	pbReq, ok := req.(*pb.DelKeysRequest)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCRequestType, "expecting *pb.DelKeysRequest, received %T", req)
		return nil, err
	}
	// TODO : validate protobuf
	return NewDelKeysRequestFromPB(pbReq), nil
}

func encodeDelKeysGRPCResponse(ctx context.Context, resp interface{}) (*pb.DelKeysResponse, error) {
	domResp, ok := resp.(*DelKeysResponse)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCResponseType, "expecting *DelKeysResponse, received %T", resp)
		return nil, err
	}
	return NewPBFromDelKeysResponse(domResp), nil
}

func decodePublicKeysGRPCRequest(ctx context.Context, req interface{}) (*PublicKeysRequest, error) {
	pbReq, ok := req.(*pb.PublicKeysRequest)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCRequestType, "expecting *pb.PublicKeysRequest, received %T", req)
		return nil, err
	}
	// TODO : validate protobuf
	return NewPublicKeysRequestFromPB(pbReq), nil
}

func encodePublicKeysGRPCResponse(ctx context.Context, resp interface{}) (*pb.PublicKeysResponse, error) {
	domResp, ok := resp.(*PublicKeysResponse)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCResponseType, "expecting *PublicKeysResponse, received %T", resp)
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

// Auth protobuf implementation : no streaming for Auth
func (s *grpcServer) Auth(ctx context.Context, req *pb.AuthRequest) (*pb.AuthResponse, error) {
	decReq, err := decodeAuthGRPCRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	resp, err := s.svc.Auth(ctx, decReq)
	if err != nil {
		return nil, err
	}
	pbResp, err := encodeAuthGRPCResponse(ctx, resp)
	return pbResp, nil
}

// Register protobuf implementation : no streaming for Register
func (s *grpcServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	decReq, err := decodeRegisterGRPCRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	resp, err := s.svc.Register(ctx, decReq)
	if err != nil {
		return nil, err
	}
	pbResp, err := encodeRegisterGRPCResponse(ctx, resp)
	return pbResp, nil
}

// UpdateKeys protobuf implementation : no streaming for UpdateKeys
func (s *grpcServer) UpdateKeys(ctx context.Context, req *pb.UpdateKeysRequest) (*pb.UpdateKeysResponse, error) {
	decReq, err := decodeUpdateKeysGRPCRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	resp, err := s.svc.UpdateKeys(ctx, decReq)
	if err != nil {
		return nil, err
	}
	pbResp, err := encodeUpdateKeysGRPCResponse(ctx, resp)
	return pbResp, nil
}

// ListKeys protobuf implementation : half duplex for ListKeys
func (s *grpcServer) ListKeys(req *pb.ListKeysRequest, stream pb.Keys_ListKeysServer) error {
	ctx := context.Background()
	decReq, err := decodeListKeysGRPCRequest(ctx, req)
	if err != nil {
		return err
	}
	listResp, err := s.svc.ListKeys(ctx, decReq)
	for i := range listResp {
		resp, err := encodeListKeysGRPCResponse(ctx, listResp[i])
		if err != nil {
			return err
		}
		err = stream.Send(resp)
		if err != nil {
			return err
		}
	}
	return err
}

// DelKeys protobuf implementation : no streaming for DelKeys
func (s *grpcServer) DelKeys(ctx context.Context, req *pb.DelKeysRequest) (*pb.DelKeysResponse, error) {
	decReq, err := decodeDelKeysGRPCRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	resp, err := s.svc.DelKeys(ctx, decReq)
	if err != nil {
		return nil, err
	}
	pbResp, err := encodeDelKeysGRPCResponse(ctx, resp)
	return pbResp, nil
}

// PublicKeys protobuf implementation : no streaming for PublicKeys
func (s *grpcServer) PublicKeys(ctx context.Context, req *pb.PublicKeysRequest) (*pb.PublicKeysResponse, error) {
	decReq, err := decodePublicKeysGRPCRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	resp, err := s.svc.PublicKeys(ctx, decReq)
	if err != nil {
		return nil, err
	}
	pbResp, err := encodePublicKeysGRPCResponse(ctx, resp)
	return pbResp, nil
}
