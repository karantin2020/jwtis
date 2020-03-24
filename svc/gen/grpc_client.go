package gen

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	errors "github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"

	"github.com/karantin2020/jwtis"

	kitGRPC "github.com/go-kit/kit/transport/grpc"
	pb "github.com/karantin2020/jwtis/svc/pb"
)

// ClientOption func
type ClientOption func(*grpcClient)

// ClientRequestFunc func
type ClientRequestFunc func(context.Context, *metadata.MD) context.Context

// ClientResponseFunc func
type ClientResponseFunc func(context.Context, metadata.MD, metadata.MD) context.Context

// ClientBefore func
func ClientBefore(before ...ClientRequestFunc) ClientOption {
	return func(c *grpcClient) { c.before = append(c.before, before...) }
}

// ClientAfter func
func ClientAfter(after ...ClientResponseFunc) ClientOption {
	return func(c *grpcClient) { c.after = append(c.after, after...) }
}

// ClientService interface
type ClientService interface {
	Service
	ApplyExtraOptions(options ...ClientOption)
	ReceiveListKeys() chan ListKeysResponse
	CallListKeys(extCtx context.Context, inReq *ListKeysRequest) error
	FetchListKeys(extCtx context.Context, inReq *ListKeysRequest) ([]*ListKeysResponse, error)
}

type grpcClient struct {
	log                log.Logger
	NewJWTEndpoint     endpoint.Endpoint
	RenewJWTEndpoint   endpoint.Endpoint
	RevokeJWTEndpoint  endpoint.Endpoint
	AuthEndpoint       endpoint.Endpoint
	RegisterEndpoint   endpoint.Endpoint
	UpdateKeysEndpoint endpoint.Endpoint
	receiveListKeys    chan ListKeysResponse // TODO : collect payloads from this channel
	DelKeysEndpoint    endpoint.Endpoint
	PublicKeysEndpoint endpoint.Endpoint
	PingEndpoint       endpoint.Endpoint
	ReadyEndpoint      endpoint.Endpoint
	directClient       pb.JWTISServiceClient
	before             []ClientRequestFunc
	after              []ClientResponseFunc
}

// Log method
func (c *grpcClient) Log() log.Logger {
	return c.log
}

// ApplyExtraOptions method
func (c *grpcClient) ApplyExtraOptions(options ...ClientOption) {
	for _, option := range options {
		option(c)
	}
}

// ReceiveListKeys getter for receiveListKeys chan ListKeysResponse
func (c *grpcClient) ReceiveListKeys() chan ListKeysResponse {
	return c.receiveListKeys
}

// NewClient constructor
func NewClient(conn *grpc.ClientConn, logger log.Logger, options ...kitGRPC.ClientOption) ClientService {
	result := &grpcClient{
		log:          logger,
		directClient: pb.NewJWTISServiceClient(conn),
		NewJWTEndpoint: kitGRPC.NewClient(
			conn,
			"pb.JWTISService",
			"NewJWT",
			encodeNewJWTGRPCRequest(logger),
			decodeNewJWTGRPCResponse(logger),
			&pb.NewJWTResponse{},
			options...,
		).Endpoint(),
		RenewJWTEndpoint: kitGRPC.NewClient(
			conn,
			"pb.JWTISService",
			"RenewJWT",
			encodeRenewJWTGRPCRequest(logger),
			decodeRenewJWTGRPCResponse(logger),
			&pb.RenewJWTResponse{},
			options...,
		).Endpoint(),
		RevokeJWTEndpoint: kitGRPC.NewClient(
			conn,
			"pb.JWTISService",
			"RevokeJWT",
			encodeRevokeJWTGRPCRequest(logger),
			decodeRevokeJWTGRPCResponse(logger),
			&pb.RevokeJWTResponse{},
			options...,
		).Endpoint(),
		AuthEndpoint: kitGRPC.NewClient(
			conn,
			"pb.JWTISService",
			"Auth",
			encodeAuthGRPCRequest(logger),
			decodeAuthGRPCResponse(logger),
			&pb.AuthResponse{},
			options...,
		).Endpoint(),
		RegisterEndpoint: kitGRPC.NewClient(
			conn,
			"pb.JWTISService",
			"Register",
			encodeRegisterGRPCRequest(logger),
			decodeRegisterGRPCResponse(logger),
			&pb.RegisterResponse{},
			options...,
		).Endpoint(),
		UpdateKeysEndpoint: kitGRPC.NewClient(
			conn,
			"pb.JWTISService",
			"UpdateKeys",
			encodeUpdateKeysGRPCRequest(logger),
			decodeUpdateKeysGRPCResponse(logger),
			&pb.UpdateKeysResponse{},
			options...,
		).Endpoint(),
		receiveListKeys: make(chan ListKeysResponse),
		DelKeysEndpoint: kitGRPC.NewClient(
			conn,
			"pb.JWTISService",
			"DelKeys",
			encodeDelKeysGRPCRequest(logger),
			decodeDelKeysGRPCResponse(logger),
			&pb.DelKeysResponse{},
			options...,
		).Endpoint(),
		PublicKeysEndpoint: kitGRPC.NewClient(
			conn,
			"pb.JWTISService",
			"PublicKeys",
			encodePublicKeysGRPCRequest(logger),
			decodePublicKeysGRPCResponse(logger),
			&pb.PublicKeysResponse{},
			options...,
		).Endpoint(),
		PingEndpoint: kitGRPC.NewClient(
			conn,
			"pb.JWTISService",
			"Ping",
			encodePingGRPCRequest(logger),
			decodePingGRPCResponse(logger),
			&pb.PingResponse{},
			options...,
		).Endpoint(),
		ReadyEndpoint: kitGRPC.NewClient(
			conn,
			"pb.JWTISService",
			"Ready",
			encodeReadyGRPCRequest(logger),
			decodeReadyGRPCResponse(logger),
			&pb.ReadyResponse{},
			options...,
		).Endpoint(),
	}
	return result
}

func encodeNewJWTGRPCRequest(logger log.Logger) func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		sReq, ok := req.(*NewJWTRequest)
		if !ok {
			err := errors.Errorf("expecting *NewJWTRequestRequest, received %T", req)
			return nil, err
		}
		var claims []byte
		var err error
		if sReq.Claims == nil {
			claims = []byte("{}")
		} else {
			claims, err = json.Marshal(sReq.Claims)
			if err != nil {
				return nil, errors.Wrap(err, "error marshal claims")
			}
		}
		pbReq := &pb.NewJWTRequest{
			KID:    sReq.KID,
			Claims: claims,
		}
		return pbReq, nil
	}
}

func decodeNewJWTGRPCResponse(logger log.Logger) func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, resp interface{}) (interface{}, error) {
		domResp, ok := resp.(*pb.NewJWTResponse)
		if !ok {
			err := errors.Errorf("expecting *pb.NewJWTResponse, received %T", resp)
			return nil, err
		}
		return NewNewJWTResponseFromPB(domResp), nil
	}
}

func encodeRenewJWTGRPCRequest(logger log.Logger) func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		pbReq, ok := req.(*RenewJWTRequest)
		if !ok {
			err := errors.Errorf("expecting *RenewJWTRequestRequest, received %T", req)
			return nil, err
		}
		return NewPBFromRenewJWTRequest(pbReq), nil
	}
}

func decodeRenewJWTGRPCResponse(logger log.Logger) func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, resp interface{}) (interface{}, error) {
		domResp, ok := resp.(*pb.RenewJWTResponse)
		if !ok {
			err := errors.Errorf("expecting *pb.RenewJWTResponse, received %T", resp)
			return nil, err
		}
		return NewRenewJWTResponseFromPB(domResp), nil
	}
}

func encodeRevokeJWTGRPCRequest(logger log.Logger) func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		pbReq, ok := req.(*RevokeJWTRequest)
		if !ok {
			err := errors.Errorf("expecting *RevokeJWTRequestRequest, received %T", req)
			return nil, err
		}
		return NewPBFromRevokeJWTRequest(pbReq), nil
	}
}

func decodeRevokeJWTGRPCResponse(logger log.Logger) func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, resp interface{}) (interface{}, error) {
		domResp, ok := resp.(*pb.RevokeJWTResponse)
		if !ok {
			err := errors.Errorf("expecting *pb.RevokeJWTResponse, received %T", resp)
			return nil, err
		}
		return NewRevokeJWTResponseFromPB(domResp), nil
	}
}

func encodeAuthGRPCRequest(logger log.Logger) func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		pbReq, ok := req.(*AuthRequest)
		if !ok {
			err := errors.Errorf("expecting *AuthRequestRequest, received %T", req)
			return nil, err
		}
		return NewPBFromAuthRequest(pbReq), nil
	}
}

func decodeAuthGRPCResponse(logger log.Logger) func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, resp interface{}) (interface{}, error) {
		domResp, ok := resp.(*pb.AuthResponse)
		if !ok {
			err := errors.Errorf("expecting *pb.AuthResponse, received %T", resp)
			return nil, err
		}
		return NewAuthResponseFromPB(domResp), nil
	}
}

func encodeRegisterGRPCRequest(logger log.Logger) func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		pbReq, ok := req.(*RegisterRequest)
		if !ok {
			err := errors.Errorf("expecting *RegisterRequestRequest, received %T", req)
			return nil, err
		}
		return NewPBFromRegisterRequest(pbReq), nil
	}
}

func decodeRegisterGRPCResponse(logger log.Logger) func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, resp interface{}) (interface{}, error) {
		msg, ok := resp.(*pb.RegisterResponse)
		if !ok {
			err := errors.Errorf("expecting *pb.RegisterResponse, received %T", resp)
			return nil, err
		}
		var result = RegisterResponse{
			KID:     msg.KID,
			AuthJWT: msg.AuthJWT,
		}
		var sigKey jose.JSONWebKey
		err := json.Unmarshal(msg.PubSigKey, &sigKey)
		if err != nil {
			return nil, err
		}
		var encKey jose.JSONWebKey
		err = json.Unmarshal(msg.PubEncKey, &encKey)
		if err != nil {
			return nil, err
		}
		result.Keys = &jwtis.SigEncKeys{
			Sig:             sigKey,
			Enc:             encKey,
			Expiry:          jwt.NumericDate(msg.Expiry),
			Valid:           msg.Valid,
			RefreshStrategy: msg.RefreshStrategy,
		}
		return &result, nil
	}
}

func encodeUpdateKeysGRPCRequest(logger log.Logger) func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		pbReq, ok := req.(*UpdateKeysRequest)
		if !ok {
			err := errors.Errorf("expecting *UpdateKeysRequestRequest, received %T", req)
			return nil, err
		}
		return NewPBFromUpdateKeysRequest(pbReq), nil
	}
}

func decodeUpdateKeysGRPCResponse(logger log.Logger) func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, resp interface{}) (interface{}, error) {
		msg, ok := resp.(*pb.UpdateKeysResponse)
		if !ok {
			err := errors.Errorf("expecting *pb.UpdateKeysResponse, received %T", resp)
			return nil, err
		}
		var result = UpdateKeysResponse{
			KID:     msg.KID,
			AuthJWT: msg.AuthJWT,
		}
		var sigKey jose.JSONWebKey
		err := json.Unmarshal(msg.PubSigKey, &sigKey)
		if err != nil {
			return nil, err
		}
		var encKey jose.JSONWebKey
		err = json.Unmarshal(msg.PubEncKey, &encKey)
		if err != nil {
			return nil, err
		}
		result.Keys = &jwtis.SigEncKeys{
			Sig:             sigKey,
			Enc:             encKey,
			Expiry:          jwt.NumericDate(msg.Expiry),
			Valid:           msg.Valid,
			RefreshStrategy: msg.RefreshStrategy,
		}
		return &result, nil
	}
}

func encodeDelKeysGRPCRequest(logger log.Logger) func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		pbReq, ok := req.(*DelKeysRequest)
		if !ok {
			err := errors.Errorf("expecting *DelKeysRequestRequest, received %T", req)
			return nil, err
		}
		return NewPBFromDelKeysRequest(pbReq), nil
	}
}

func decodeDelKeysGRPCResponse(logger log.Logger) func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, resp interface{}) (interface{}, error) {
		domResp, ok := resp.(*pb.DelKeysResponse)
		if !ok {
			err := errors.Errorf("expecting *pb.DelKeysResponse, received %T", resp)
			return nil, err
		}
		return NewDelKeysResponseFromPB(domResp), nil
	}
}

func encodePublicKeysGRPCRequest(logger log.Logger) func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		pbReq, ok := req.(*PublicKeysRequest)
		if !ok {
			err := errors.Errorf("expecting *PublicKeysRequestRequest, received %T", req)
			return nil, err
		}
		return NewPBFromPublicKeysRequest(pbReq), nil
	}
}

func decodePublicKeysGRPCResponse(logger log.Logger) func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, resp interface{}) (interface{}, error) {
		domResp, ok := resp.(*pb.PublicKeysResponse)
		if !ok {
			err := errors.Errorf("expecting *pb.PublicKeysResponse, received %T", resp)
			return nil, err
		}
		var sigKey jose.JSONWebKey
		err := json.Unmarshal(domResp.PubSigKey, &sigKey)
		if err != nil {
			return nil, errors.Wrap(err, "error unmarshal sigKey")
		}
		var encKey jose.JSONWebKey
		err = json.Unmarshal(domResp.PubEncKey, &encKey)
		if err != nil {
			return nil, errors.Wrap(err, "error unmarshal encKey")
		}
		var result = PublicKeysResponse{
			KID: domResp.KID,
			Keys: &jwtis.SigEncKeys{
				Expiry: jwt.NumericDate(domResp.Expiry),
				Valid:  domResp.Valid,
				Sig:    sigKey,
				Enc:    encKey,
			},
		}
		// NewPublicKeysResponseFromPB(domResp)
		return &result, nil
	}
}

func encodePingGRPCRequest(logger log.Logger) func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		pbReq, ok := req.(*PingRequest)
		if !ok {
			err := errors.Errorf("expecting *PingRequestRequest, received %T", req)
			return nil, err
		}
		return NewPBFromPingRequest(pbReq), nil
	}
}

func decodePingGRPCResponse(logger log.Logger) func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, resp interface{}) (interface{}, error) {
		domResp, ok := resp.(*pb.PingResponse)
		if !ok {
			err := errors.Errorf("expecting *pb.PingResponse, received %T", resp)
			return nil, err
		}
		return NewPingResponseFromPB(domResp), nil
	}
}

func encodeReadyGRPCRequest(logger log.Logger) func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		pbReq, ok := req.(*ReadyRequest)
		if !ok {
			err := errors.Errorf("expecting *ReadyRequestRequest, received %T", req)
			return nil, err
		}
		return NewPBFromReadyRequest(pbReq), nil
	}
}

func decodeReadyGRPCResponse(logger log.Logger) func(context.Context, interface{}) (interface{}, error) {
	return func(ctx context.Context, resp interface{}) (interface{}, error) {
		domResp, ok := resp.(*pb.ReadyResponse)
		if !ok {
			err := errors.Errorf("expecting *pb.ReadyResponse, received %T", resp)
			return nil, err
		}
		return NewReadyResponseFromPB(domResp), nil
	}
}

// NewJWT client method
func (c *grpcClient) NewJWT(ctx context.Context, req *NewJWTRequest) (*NewJWTResponse, error) {
	resp, err := c.NewJWTEndpoint(ctx, req)
	if err != nil {
		return nil, err
	}
	domResp, ok := resp.(*NewJWTResponse)
	if !ok {
		err := errors.Errorf("expecting *NewJWTResponse, received %T", resp)
		return nil, err
	}
	return domResp, nil
}

// RenewJWT client method
func (c *grpcClient) RenewJWT(ctx context.Context, req *RenewJWTRequest) (*RenewJWTResponse, error) {
	resp, err := c.RenewJWTEndpoint(ctx, req)
	if err != nil {
		return nil, err
	}
	domResp, ok := resp.(*RenewJWTResponse)
	if !ok {
		err := errors.Errorf("expecting *RenewJWTResponse, received %T", resp)
		return nil, err
	}
	return domResp, nil
}

// RevokeJWT client method
func (c *grpcClient) RevokeJWT(ctx context.Context, req *RevokeJWTRequest) (*RevokeJWTResponse, error) {
	resp, err := c.RevokeJWTEndpoint(ctx, req)
	if err != nil {
		return nil, err
	}
	domResp, ok := resp.(*RevokeJWTResponse)
	if !ok {
		err := errors.Errorf("expecting *RevokeJWTResponse, received %T", resp)
		return nil, err
	}
	return domResp, nil
}

// Auth client method
func (c *grpcClient) Auth(ctx context.Context, req *AuthRequest) (*AuthResponse, error) {
	resp, err := c.AuthEndpoint(ctx, req)
	if err != nil {
		return nil, err
	}
	domResp, ok := resp.(*AuthResponse)
	if !ok {
		err := errors.Errorf("expecting *AuthResponse, received %T", resp)
		return nil, err
	}
	return domResp, nil
}

// Register client method
func (c *grpcClient) Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	resp, err := c.RegisterEndpoint(ctx, req)
	if err != nil {
		return nil, err
	}
	domResp, ok := resp.(*RegisterResponse)
	if !ok {
		err := errors.Errorf("expecting *RegisterResponse, received %T", resp)
		return nil, err
	}
	return domResp, nil
}

// UpdateKeys client method
func (c *grpcClient) UpdateKeys(ctx context.Context, req *UpdateKeysRequest) (*UpdateKeysResponse, error) {
	resp, err := c.UpdateKeysEndpoint(ctx, req)
	if err != nil {
		return nil, err
	}
	domResp, ok := resp.(*UpdateKeysResponse)
	if !ok {
		err := errors.Errorf("expecting *UpdateKeysResponse, received %T", resp)
		return nil, err
	}
	return domResp, nil
}

// ListKeys method unusable : client has to implement Service interface for half duplex ListKeys
func (c *grpcClient) ListKeys(req *pb.ListKeysRequest, stream pb.JWTISService_ListKeysServer) error {
	return nil
}

// DelKeys client method
func (c *grpcClient) DelKeys(ctx context.Context, req *DelKeysRequest) (*DelKeysResponse, error) {
	resp, err := c.DelKeysEndpoint(ctx, req)
	if err != nil {
		return nil, err
	}
	domResp, ok := resp.(*DelKeysResponse)
	if !ok {
		err := errors.Errorf("expecting *DelKeysResponse, received %T", resp)
		return nil, err
	}
	return domResp, nil
}

// PublicKeys client method
func (c *grpcClient) PublicKeys(ctx context.Context, req *PublicKeysRequest) (*PublicKeysResponse, error) {
	resp, err := c.PublicKeysEndpoint(ctx, req)
	if err != nil {
		return nil, err
	}
	domResp, ok := resp.(*PublicKeysResponse)
	if !ok {
		err := errors.Errorf("expecting *PublicKeysResponse, received %T", resp)
		return nil, err
	}
	return domResp, nil
}

// Ping client method
func (c *grpcClient) Ping(ctx context.Context, req *PingRequest) (*PingResponse, error) {
	resp, err := c.PingEndpoint(ctx, req)
	if err != nil {
		return nil, err
	}
	domResp, ok := resp.(*PingResponse)
	if !ok {
		err := errors.Errorf("expecting *PingResponse, received %T", resp)
		return nil, err
	}
	return domResp, nil
}

// Ready client method
func (c *grpcClient) Ready(ctx context.Context, req *ReadyRequest) (*ReadyResponse, error) {
	resp, err := c.ReadyEndpoint(ctx, req)
	if err != nil {
		return nil, err
	}
	domResp, ok := resp.(*ReadyResponse)
	if !ok {
		err := errors.Errorf("expecting *ReadyResponse, received %T", resp)
		return nil, err
	}
	return domResp, nil
}

// CallListKeys method usable : implementation of direct client for ListKeys - half duplex
func (c *grpcClient) CallListKeys(extCtx context.Context, inReq *ListKeysRequest) error {
	var err error
	ctx, cancel := context.WithCancel(extCtx)

	ctx = context.WithValue(ctx, kitGRPC.ContextKeyRequestMethod, "CallListKeys")

	req := NewPBFromListKeysRequest(inReq)

	md := &metadata.MD{}
	for _, f := range c.before {
		ctx = f(ctx, md)
	}
	ctx = metadata.NewOutgoingContext(ctx, *md)

	var header, trailer metadata.MD

	stream, err := c.directClient.ListKeys(ctx, req, grpc.Header(&header), grpc.Trailer(&trailer))
	if err != nil {
		c.log.Log("client_error", err)
		return err
	}

	var closing = func() {
		cancel()
		stream.CloseSend()
		for _, f := range c.after {
			ctx = f(ctx, header, trailer)
		}
	}
	// receiving from server loop
	for {
		message, err := stream.Recv()
		if err == io.EOF {
			closing()
			// read done.
			return nil
		}
		if err != nil {
			// TODO : if server needs to close, with an error, which is a known error (no-error)
			//if err == CloseCommunication {
			//    closing()
			//    return "",0,0,0,"",[]byte{},[]byte{},false,false,false, nil
			//}
			c.log.Log("client_error", fmt.Sprintf("server return error : %v\n", err))
			closing()
			return err
		}

		sigKey, err := json.Marshal(message.PubSigKey)
		if err != nil {
			return errors.Wrap(err, "error marshal Sig key")
		}
		encKey, err := json.Marshal(message.PubEncKey)
		if err != nil {
			return errors.Wrap(err, "error marshal Enc key")
		}
		var domResp = ListKeysResponse{
			KID: message.KID,
			Keys: jwtis.KeysInfoSet{
				Expiry:          message.Expiry,
				AuthTTL:         message.AuthTTL,
				RefreshTTL:      message.RefreshTTL,
				RefreshStrategy: message.RefreshStrategy,
				Locked:          message.Locked,
				Valid:           message.Valid,
				Expired:         message.Expired,
				Enc:             encKey,
				Sig:             sigKey,
			},
		}
		fmt.Printf("in CallList send in chan: %s\n", domResp.KID)
		// domResp := NewListKeysResponseFromPB(message)
		c.receiveListKeys <- domResp // writing payloads to this channel, so dev can collect them
	}

	return nil
}

func (c *grpcClient) FetchListKeys(extCtx context.Context, inReq *ListKeysRequest) ([]*ListKeysResponse, error) {
	// ml := &sync.Mutex{}
	listKeys := []*ListKeysResponse{}
	var err error
	ctx, cancel := context.WithCancel(extCtx)

	ctx = context.WithValue(ctx, kitGRPC.ContextKeyRequestMethod, "CallListKeys")

	req := NewPBFromListKeysRequest(inReq)

	md := &metadata.MD{}
	for _, f := range c.before {
		ctx = f(ctx, md)
	}
	ctx = metadata.NewOutgoingContext(ctx, *md)

	var header, trailer metadata.MD

	stream, err := c.directClient.ListKeys(ctx, req, grpc.Header(&header), grpc.Trailer(&trailer))
	if err != nil {
		c.log.Log("client_error", err)
		return nil, err
	}

	var closing = func() {
		cancel()
		stream.CloseSend()
		for _, f := range c.after {
			ctx = f(ctx, header, trailer)
		}
	}
	// receiving from server loop
	for {
		message, err := stream.Recv()
		if err == io.EOF {
			closing()
			// read done.
			return listKeys, nil
		}
		if err != nil {
			// TODO : if server needs to close, with an error, which is a known error (no-error)
			//if err == CloseCommunication {
			//    closing()
			//    return listKeys, nil
			//}
			c.log.Log("client_error", fmt.Sprintf("server return error : %v\n", err))
			closing()
			return nil, err
		}

		sigKey, err := json.Marshal(message.PubSigKey)
		if err != nil {
			return nil, errors.Wrap(err, "error marshal Sig key")
		}
		encKey, err := json.Marshal(message.PubEncKey)
		if err != nil {
			return nil, errors.Wrap(err, "error marshal Enc key")
		}
		var domResp = ListKeysResponse{
			KID: message.KID,
			Keys: jwtis.KeysInfoSet{
				Expiry:          message.Expiry,
				AuthTTL:         message.AuthTTL,
				RefreshTTL:      message.RefreshTTL,
				RefreshStrategy: message.RefreshStrategy,
				Locked:          message.Locked,
				Valid:           message.Valid,
				Expired:         message.Expired,
				Enc:             encKey,
				Sig:             sigKey,
			},
		}
		listKeys = append(listKeys, &domResp)
	}

	return listKeys, nil
}
