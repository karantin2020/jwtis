package keys

import (
	"context"
	"encoding/json"

	"go.uber.org/zap"

	api "github.com/karantin2020/jwtis/api/keys/v1"

	"github.com/karantin2020/jwtis/pkg/errdef"
	errors "github.com/pkg/errors"
)

type grpcServer struct {
	logger *zap.Logger
	svc    Service
	api.UnimplementedKeysServer
}

// NewKeysServer creates new KeysServer instance
func NewKeysServer(service Service, log *zap.Logger) api.KeysServer {
	return &grpcServer{
		logger: log.With(zap.String("component", "keys_grpc_server")),
		svc:    service,
	}
}

func decodeAuthGRPCRequest(ctx context.Context, req interface{}) (*AuthRequest, error) {
	pbReq, ok := req.(*api.AuthRequest)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCRequestType, "expecting *pb.AuthRequest, received %T", req)
		return nil, err
	}
	// TODO : validate protobuf
	return NewAuthRequestFromPB(pbReq), nil
}

func encodeAuthGRPCResponse(ctx context.Context, resp interface{}) (*api.AuthResponse, error) {
	domResp, ok := resp.(*AuthResponse)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCResponseType, "expecting *AuthResponse, received %T", resp)
		return nil, err
	}
	return NewPBFromAuthResponse(domResp), nil
}

func decodeRegisterGRPCRequest(ctx context.Context, req interface{}) (*RegisterRequest, error) {
	pbReq, ok := req.(*api.RegisterRequest)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCRequestType, "expecting *pb.RegisterRequest, received %T", req)
		return nil, err
	}
	// TODO : validate protobuf
	return NewRegisterRequestFromPB(pbReq), nil
}

func encodeRegisterGRPCResponse(ctx context.Context, resp interface{}) (*api.RegisterResponse, error) {
	msg, ok := resp.(*RegisterResponse)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCResponseType, "expecting *RegisterResponse, received %T", resp)
		return nil, err
	}
	var result = api.RegisterResponse{
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
	pbReq, ok := req.(*api.UpdateKeysRequest)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCRequestType, "expecting *pb.UpdateKeysRequest, received %T", req)
		return nil, err
	}
	// TODO : validate protobuf
	return NewUpdateKeysRequestFromPB(pbReq), nil
}

func encodeUpdateKeysGRPCResponse(ctx context.Context, resp interface{}) (*api.UpdateKeysResponse, error) {
	msg, ok := resp.(*UpdateKeysResponse)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCResponseType, "expecting *UpdateKeysResponse, received %T", resp)
		return nil, err
	}
	var result = api.UpdateKeysResponse{
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
	pbReq, ok := req.(*api.ListKeysRequest)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCRequestType, "expecting *pb.ListKeysRequest, received %T", req)
		return nil, err
	}
	// TODO : validate protobuf
	return NewListKeysRequestFromPB(pbReq), nil
}

// streaming encoder : nothing to do, just pass it over
// it will be service responsibility to encode
func encodeListKeysGRPCResponse(ctx context.Context, resp interface{}) (*api.ListKeysResponse, error) {
	domResp, ok := resp.(*ListKeysResponse)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCResponseType, "expecting *ListKeysResponse, received %T", resp)
		return nil, err
	}
	return NewPBFromListKeysResponse(domResp), nil
}

func decodeDelKeysGRPCRequest(ctx context.Context, req interface{}) (*DelKeysRequest, error) {
	pbReq, ok := req.(*api.DelKeysRequest)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCRequestType, "expecting *pb.DelKeysRequest, received %T", req)
		return nil, err
	}
	// TODO : validate protobuf
	return NewDelKeysRequestFromPB(pbReq), nil
}

func encodeDelKeysGRPCResponse(ctx context.Context, resp interface{}) (*api.DelKeysResponse, error) {
	domResp, ok := resp.(*DelKeysResponse)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCResponseType, "expecting *DelKeysResponse, received %T", resp)
		return nil, err
	}
	return NewPBFromDelKeysResponse(domResp), nil
}

func decodePublicKeysGRPCRequest(ctx context.Context, req interface{}) (*PublicKeysRequest, error) {
	pbReq, ok := req.(*api.PublicKeysRequest)
	if !ok {
		err := errors.Wrapf(errdef.ErrNotExpectedGRPCRequestType, "expecting *pb.PublicKeysRequest, received %T", req)
		return nil, err
	}
	// TODO : validate protobuf
	return NewPublicKeysRequestFromPB(pbReq), nil
}

func encodePublicKeysGRPCResponse(ctx context.Context, resp interface{}) (*api.PublicKeysResponse, error) {
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
	var result = api.PublicKeysResponse{
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
func (s *grpcServer) Auth(ctx context.Context, req *api.AuthRequest) (*api.AuthResponse, error) {
	decReq := NewAuthRequestFromPB(req)
	resp, err := s.svc.Auth(ctx, decReq)
	if err != nil {
		s.logger.Error("authentication error", zap.String("operation", "auth"), zap.Error(err))
		return nil, err
	}
	return NewPBFromAuthResponse(resp), nil
}

// Register protobuf implementation : no streaming for Register
func (s *grpcServer) Register(ctx context.Context, req *api.RegisterRequest) (*api.RegisterResponse, error) {
	decReq := NewRegisterRequestFromPB(req)
	resp, err := s.svc.Register(ctx, decReq)
	if err != nil {
		s.logger.Error("register error", zap.String("operation", "register"), zap.Error(err))
		return nil, err
	}
	pbResp, err := encodeRegisterGRPCResponse(ctx, resp)
	return pbResp, nil
}

// UpdateKeys protobuf implementation : no streaming for UpdateKeys
func (s *grpcServer) UpdateKeys(ctx context.Context, req *api.UpdateKeysRequest) (*api.UpdateKeysResponse, error) {
	decReq := NewUpdateKeysRequestFromPB(req)
	resp, err := s.svc.UpdateKeys(ctx, decReq)
	if err != nil {
		s.logger.Error("update keys error", zap.String("operation", "updateKeys"), zap.Error(err))
		return nil, err
	}
	pbResp, err := encodeUpdateKeysGRPCResponse(ctx, resp)
	return pbResp, nil
}

// ListKeys protobuf implementation : half duplex for ListKeys
func (s *grpcServer) ListKeys(req *api.ListKeysRequest, stream api.Keys_ListKeysServer) error {
	ctx := context.Background()
	decReq := NewListKeysRequestFromPB(req)
	listResp, err := s.svc.ListKeys(ctx, decReq)
	for _, message := range listResp {
		sigKey, err := json.Marshal(message.Keys.Sig)
		if err != nil {
			s.logger.Error("marshal sig key error", zap.String("operation", "listKeys"), zap.Error(err))
			return errors.Wrap(err, "error marshal Sig key")
		}
		encKey, err := json.Marshal(message.Keys.Enc)
		if err != nil {
			s.logger.Error("marshal enc key error", zap.String("operation", "listKeys"), zap.Error(err))
			return errors.Wrap(err, "error marshal Enc key")
		}
		var resp = &api.ListKeysResponse{
			KID:             message.KID,
			Expiry:          message.Keys.Expiry,
			AuthTTL:         message.Keys.AuthTTL,
			RefreshTTL:      message.Keys.RefreshTTL,
			RefreshStrategy: message.Keys.RefreshStrategy,
			PubSigKey:       sigKey,
			PubEncKey:       encKey,
			Locked:          message.Keys.Locked,
			Valid:           message.Keys.Valid,
			Expired:         message.Keys.Expired,
		}
		err = stream.Send(resp)
		if err != nil {
			return err
		}
	}
	return err
}

// DelKeys protobuf implementation : no streaming for DelKeys
func (s *grpcServer) DelKeys(ctx context.Context, req *api.DelKeysRequest) (*api.DelKeysResponse, error) {
	decReq := NewDelKeysRequestFromPB(req)
	resp, err := s.svc.DelKeys(ctx, decReq)
	if err != nil {
		s.logger.Error("delete keys error", zap.String("operation", "delKeys"), zap.Error(err))
		return nil, err
	}
	return NewPBFromDelKeysResponse(resp), nil
}

// PublicKeys protobuf implementation : no streaming for PublicKeys
func (s *grpcServer) PublicKeys(ctx context.Context, req *api.PublicKeysRequest) (*api.PublicKeysResponse, error) {
	decReq := NewPublicKeysRequestFromPB(req)
	resp, err := s.svc.PublicKeys(ctx, decReq)
	if err != nil {
		s.logger.Error("get public keys error", zap.String("operation", "publicKeys"), zap.Error(err))
		return nil, err
	}
	pbResp, err := encodePublicKeysGRPCResponse(ctx, resp)
	return pbResp, nil
}
