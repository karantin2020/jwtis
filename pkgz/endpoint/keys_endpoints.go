package endpoint

import (
	"context"

	"github.com/rs/zerolog"

	"github.com/go-kit/kit/endpoint"
	"github.com/karantin2020/jwtis"
	"github.com/karantin2020/jwtis/pkg/service"
)

// KeysEndpoints collects all of the KeysEndpoints that compose JWTService. It's meant to
// be used as a helper struct, to collect all of the KeysEndpoints into a single
// parameter
type KeysEndpoints struct {
	RegisterEndpoint   endpoint.Endpoint
	UpdateKeysEndpoint endpoint.Endpoint
	ListKeysEndpoint   endpoint.Endpoint
	DelKeysEndpoint    endpoint.Endpoint
	PublicKeysEndpoint endpoint.Endpoint
}

// NewKeysEndpoints returns Endpoints that wraps the provided server, and wires in all of the
// expected endpoint middlewares via the various parameters.
func NewKeysEndpoints(svc service.KeysService, logger zerolog.Logger) KeysEndpoints {
	var registerEndpoint endpoint.Endpoint
	registerEndpoint = MakeRegisterEndpoint(svc)

	var updateKeysEndpoint endpoint.Endpoint
	updateKeysEndpoint = MakeUpdateKeysEndpoint(svc)

	var listKeysEndpoint endpoint.Endpoint
	listKeysEndpoint = MakeListKeysEndpoint(svc)

	var delKeysEndpoint endpoint.Endpoint
	delKeysEndpoint = MakeDelKeysEndpoint(svc)

	var publicKeysEndpoint endpoint.Endpoint
	publicKeysEndpoint = MakePublicKeysEndpoint(svc)

	return KeysEndpoints{
		RegisterEndpoint:   registerEndpoint,
		UpdateKeysEndpoint: updateKeysEndpoint,
		ListKeysEndpoint:   listKeysEndpoint,
		DelKeysEndpoint:    delKeysEndpoint,
		PublicKeysEndpoint: publicKeysEndpoint,
	}
}

// Register method
func (s KeysEndpoints) Register(ctx context.Context, kid string, opts *jwtis.DefaultOptions) (*jwtis.SigEncKeys, error) {
	resp, err := s.RegisterEndpoint(ctx, &OptsRequest{kid, opts})
	response := resp.(*OptsResponse).Opts
	return response, err
}

// UpdateKeys method
func (s KeysEndpoints) UpdateKeys(ctx context.Context, kid string, opts *jwtis.DefaultOptions) (*jwtis.SigEncKeys, error) {
	resp, err := s.UpdateKeysEndpoint(ctx, &OptsRequest{kid, opts})
	response := resp.(*OptsResponse).Opts
	return response, err
}

// ListKeys method
func (s KeysEndpoints) ListKeys(ctx context.Context) ([]jwtis.KeysInfoSet, error) {
	resp, err := s.ListKeysEndpoint(ctx, nil)
	response := resp.([]jwtis.KeysInfoSet)
	return response, err
}

// DelKeys method
func (s KeysEndpoints) DelKeys(ctx context.Context, kid string) error {
	_, err := s.DelKeysEndpoint(ctx, &OptsRequest{KID: kid})
	return err
}

// PublicKeys method
func (s KeysEndpoints) PublicKeys(ctx context.Context, kid string) (*jwtis.SigEncKeys, error) {
	resp, err := s.PublicKeysEndpoint(ctx, &OptsRequest{KID: kid})
	response := resp.(*jwtis.SigEncKeys)
	return response, err
}

// MakeRegisterEndpoint constructor for RegisterEndpoint
func MakeRegisterEndpoint(svc service.KeysService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(*OptsRequest)
		// req := request.(*pb.RegisterClientRequest)
		// var opts = &jwtis.DefaultOptions{
		// 	SigAlg:          req.SigAlg,
		// 	SigBits:         int(req.SigBits),
		// 	EncAlg:          req.EncAlg,
		// 	EncBits:         int(req.EncBits),
		// 	Expiry:          time.Duration(req.Expiry),
		// 	AuthTTL:         time.Duration(req.AuthTTL),
		// 	RefreshTTL:      time.Duration(req.RefreshTTL),
		// 	RefreshStrategy: req.RefreshStrategy,
		// }
		// return svc.Register(ctx, req.KID, opts)
		resp, err := svc.Register(ctx, req.KID, req.Opts)
		return &OptsResponse{
			KID:  req.KID,
			Opts: resp,
		}, err
	}
}

// MakeUpdateKeysEndpoint constructor for UpdateKeysEndpoint
func MakeUpdateKeysEndpoint(svc service.KeysService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(*OptsRequest)
		// req := request.(*pb.RegisterClientRequest)
		// var opts = &jwtis.DefaultOptions{
		// 	SigAlg:          req.SigAlg,
		// 	SigBits:         int(req.SigBits),
		// 	EncAlg:          req.EncAlg,
		// 	EncBits:         int(req.EncBits),
		// 	Expiry:          time.Duration(req.Expiry),
		// 	AuthTTL:         time.Duration(req.AuthTTL),
		// 	RefreshTTL:      time.Duration(req.RefreshTTL),
		// 	RefreshStrategy: req.RefreshStrategy,
		// }
		// return svc.UpdateKeys(ctx, req.KID, opts)
		resp, err := svc.UpdateKeys(ctx, req.KID, req.Opts)
		return &OptsResponse{
			KID:  req.KID,
			Opts: resp,
		}, err
	}
}

// MakeListKeysEndpoint constructor for ListKeysEndpoint
func MakeListKeysEndpoint(svc service.KeysService) endpoint.Endpoint {
	return func(ctx context.Context, _ interface{}) (response interface{}, err error) {
		return svc.ListKeys(ctx)
	}
}

// MakeDelKeysEndpoint constructor for DelKeysEndpoint
func MakeDelKeysEndpoint(svc service.KeysService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(*OptsRequest)
		return nil, svc.DelKeys(ctx, req.KID)
	}
}

// MakePublicKeysEndpoint constructor for PublicKeysEndpoint
func MakePublicKeysEndpoint(svc service.KeysService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(*OptsRequest)
		return svc.PublicKeys(ctx, req.KID)
	}
}

// OptsRequest collects the request parameters for that method
type OptsRequest struct {
	KID  string                `json:"kid"`
	Opts *jwtis.DefaultOptions `json:"opts"`
}

// OptsResponse collects the response parameters for that method
type OptsResponse struct {
	KID  string            `json:"kid"`
	Opts *jwtis.SigEncKeys `json:"opts"`
}
