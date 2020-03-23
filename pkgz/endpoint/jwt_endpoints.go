package endpoint

import (
	"context"

	"github.com/rs/zerolog"

	"github.com/go-kit/kit/endpoint"
	"github.com/karantin2020/jwtis/pkg/service"
)

// JWTEndpoints collects all of the JWTEndpoints that compose JWTService. It's meant to
// be used as a helper struct, to collect all of the JWTEndpoints into a single
// parameter
type JWTEndpoints struct {
	NewJWTEndpoint   endpoint.Endpoint
	RenewJWTEndpoint endpoint.Endpoint
}

// NewJWTEndpoints returns Endpoints that wraps the provided server, and wires in all of the
// expected endpoint middlewares via the various parameters.
func NewJWTEndpoints(svc service.JWTService, logger zerolog.Logger) JWTEndpoints {
	var newJWTEndpoint endpoint.Endpoint
	newJWTEndpoint = MakeNewJWTEndpoint(svc)

	var renewJWTEndpoint endpoint.Endpoint
	renewJWTEndpoint = MakeRenewJWTEndpoint(svc)

	return JWTEndpoints{
		NewJWTEndpoint:   newJWTEndpoint,
		RenewJWTEndpoint: renewJWTEndpoint,
	}
}

// NewJWT implements the service interface, so JWTEndpoints may be used as a service
func (s JWTEndpoints) NewJWT(ctx context.Context, kid string, claims map[string]interface{}) (*service.JWTPair, error) {
	resp, err := s.NewJWTEndpoint(ctx, &NewJWTRequest{KID: kid, Claims: claims})
	response := resp.(*service.JWTPair)
	return response, err
}

// RenewJWT implements the service interface, so JWTEndpoints may be used as a service
func (s JWTEndpoints) RenewJWT(ctx context.Context, kid, refresh, refreshStrategy string) (*service.JWTPair, error) {
	resp, err := s.RenewJWTEndpoint(ctx, &RenewJWTRequest{
		KID:             kid,
		RefreshToken:    refresh,
		RefreshStrategy: refreshStrategy,
	})
	response := resp.(*service.JWTPair)
	return response, err
}

// MakeNewJWTEndpoint constructs a NewJWT endpoint wrapping the service
func MakeNewJWTEndpoint(s service.JWTService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(*NewJWTRequest)
		return s.NewJWT(ctx, req.KID, req.Claims)
		// return &NewJWTResponse{
		// 	Pair: pair,
		// 	Err:  err,
		// }, nil
	}
}

// MakeRenewJWTEndpoint constructs a RenewJWT endpoint wrapping the service
func MakeRenewJWTEndpoint(s service.JWTService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(*RenewJWTRequest)
		return s.RenewJWT(ctx, req.KID, req.RefreshToken, req.RefreshStrategy)
		// return &RenewJWTResponse{
		// 	Pair: pair,
		// 	Err:  err,
		// }, nil
	}
}

// compile time assertions for our response types implementing endpoint.Failer.
var (
	_ endpoint.Failer = NewJWTResponse{}
	_ endpoint.Failer = RenewJWTResponse{}
)

// NewJWTRequest collects the request parameters for that method
type NewJWTRequest struct {
	KID    string                 `json:"kid"`
	Claims map[string]interface{} `json:"claims"`
}

// NewJWTResponse collects the response values for the same method
type NewJWTResponse struct {
	Pair *service.JWTPair `json:"pair"`
	Err  error            `json:"-"` // should be intercepted by Failed/errorEncoder
}

// Failed implements endpoint.Failer.
func (r NewJWTResponse) Failed() error { return r.Err }

// RenewJWTRequest collects the request parameters for the same method
type RenewJWTRequest struct {
	KID             string `json:"kid"`
	RefreshToken    string `json:"refresh_token"`
	RefreshStrategy string `json:"refresh_strategy"`
}

// RenewJWTResponse collects the response values for the same method
type RenewJWTResponse struct {
	Pair *service.JWTPair `json:"pair"`
	Err  error            `json:"-"`
}

// Failed implements endpoint.Failer.
func (r RenewJWTResponse) Failed() error { return r.Err }
