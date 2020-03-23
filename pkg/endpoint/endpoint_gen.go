package endpoint

import (
	endpoint "github.com/go-kit/kit/endpoint"
	service "github.com/karantin2020/jwtis/pkg/service"
)

// Endpoints collects all of the endpoints that compose a profile service. It's
// meant to be used as a helper struct, to collect all of the endpoints into a
// single parameter.
type Endpoints struct {
	NewJWTEndpoint     endpoint.Endpoint
	RenewJWTEndpoint   endpoint.Endpoint
	RevokeJWTEndpoint  endpoint.Endpoint
	AuthEndpoint       endpoint.Endpoint
	RegisterEndpoint   endpoint.Endpoint
	UpdateKeysEndpoint endpoint.Endpoint
	ListKeysEndpoint   endpoint.Endpoint
	DelKeysEndpoint    endpoint.Endpoint
	PublicKeysEndpoint endpoint.Endpoint
}

// New returns a Endpoints struct that wraps the provided service, and wires in all of the
// expected endpoint middlewares
func New(s service.JWTISService, mdw map[string][]endpoint.Middleware) Endpoints {
	eps := Endpoints{
		AuthEndpoint:       MakeAuthEndpoint(s),
		DelKeysEndpoint:    MakeDelKeysEndpoint(s),
		ListKeysEndpoint:   MakeListKeysEndpoint(s),
		NewJWTEndpoint:     MakeNewJWTEndpoint(s),
		PublicKeysEndpoint: MakePublicKeysEndpoint(s),
		RegisterEndpoint:   MakeRegisterEndpoint(s),
		RenewJWTEndpoint:   MakeRenewJWTEndpoint(s),
		RevokeJWTEndpoint:  MakeRevokeJWTEndpoint(s),
		UpdateKeysEndpoint: MakeUpdateKeysEndpoint(s),
	}
	for _, m := range mdw["NewJWT"] {
		eps.NewJWTEndpoint = m(eps.NewJWTEndpoint)
	}
	for _, m := range mdw["RenewJWT"] {
		eps.RenewJWTEndpoint = m(eps.RenewJWTEndpoint)
	}
	for _, m := range mdw["RevokeJWT"] {
		eps.RevokeJWTEndpoint = m(eps.RevokeJWTEndpoint)
	}
	for _, m := range mdw["Auth"] {
		eps.AuthEndpoint = m(eps.AuthEndpoint)
	}
	for _, m := range mdw["Register"] {
		eps.RegisterEndpoint = m(eps.RegisterEndpoint)
	}
	for _, m := range mdw["UpdateKeys"] {
		eps.UpdateKeysEndpoint = m(eps.UpdateKeysEndpoint)
	}
	for _, m := range mdw["ListKeys"] {
		eps.ListKeysEndpoint = m(eps.ListKeysEndpoint)
	}
	for _, m := range mdw["DelKeys"] {
		eps.DelKeysEndpoint = m(eps.DelKeysEndpoint)
	}
	for _, m := range mdw["PublicKeys"] {
		eps.PublicKeysEndpoint = m(eps.PublicKeysEndpoint)
	}
	return eps
}
