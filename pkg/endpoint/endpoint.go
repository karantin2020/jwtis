package endpoint

import (
	"context"

	endpoint "github.com/go-kit/kit/endpoint"
	"github.com/karantin2020/jwtis"
	service "github.com/karantin2020/jwtis/pkg/service"
)

// NewJWTRequest collects the request parameters for the NewJWT method.
type NewJWTRequest struct {
	KID    string                 `json:"kid"`
	Claims map[string]interface{} `json:"claims"`
}

// NewJWTResponse collects the response parameters for the NewJWT method.
type NewJWTResponse struct {
	Pair *service.JWTPair `json:"pair"`
	Err  error            `json:"err"`
}

// MakeNewJWTEndpoint returns an endpoint that invokes NewJWT on the service.
func MakeNewJWTEndpoint(s service.JWTISService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(*NewJWTRequest)
		pair, err := s.NewJWT(ctx, req.KID, req.Claims)
		return &NewJWTResponse{
			Err:  err,
			Pair: pair,
		}, err
	}
}

// Failed implements Failer.
func (r NewJWTResponse) Failed() error {
	return r.Err
}

// RenewJWTRequest collects the request parameters for the RenewJWT method.
type RenewJWTRequest struct {
	KID             string `json:"kid"`
	RefreshToken    string `json:"refresh_token"`
	RefreshStrategy string `json:"refresh_strategy"`
}

// RenewJWTResponse collects the response parameters for the RenewJWT method.
type RenewJWTResponse struct {
	Pair *service.JWTPair `json:"pair"`
	Err  error            `json:"err"`
}

// MakeRenewJWTEndpoint returns an endpoint that invokes RenewJWT on the service.
func MakeRenewJWTEndpoint(s service.JWTISService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(*RenewJWTRequest)
		pair, err := s.RenewJWT(ctx, req.KID, req.RefreshToken, req.RefreshStrategy)
		return &RenewJWTResponse{
			Err:  err,
			Pair: pair,
		}, err
	}
}

// Failed implements Failer.
func (r RenewJWTResponse) Failed() error {
	return r.Err
}

// RevokeJWTRequest collects the request parameters for the RevokeJWT method.
type RevokeJWTRequest struct {
	KID          string `json:"kid"`
	JwtID        string `json:"jwt_id"`
	RefreshToken string `json:"refresh_token"`
}

// RevokeJWTResponse collects the response parameters for the RevokeJWT method.
type RevokeJWTResponse struct {
	Err error `json:"err"`
}

// MakeRevokeJWTEndpoint returns an endpoint that invokes RevokeJWT on the service.
func MakeRevokeJWTEndpoint(s service.JWTISService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(*RevokeJWTRequest)
		err := s.RevokeJWT(ctx, req.KID, req.JwtID, req.RefreshToken)
		return &RevokeJWTResponse{Err: err}, err
	}
}

// Failed implements Failer.
func (r RevokeJWTResponse) Failed() error {
	return r.Err
}

// AuthRequest collects the request parameters for the Auth method.
type AuthRequest struct {
	KID string `json:"kid"`
}

// AuthResponse collects the response parameters for the Auth method.
type AuthResponse struct {
	Token string `json:"token"`
	Err   error  `json:"err"`
}

// MakeAuthEndpoint returns an endpoint that invokes Auth on the service.
func MakeAuthEndpoint(s service.JWTISService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(*AuthRequest)
		token, err := s.Auth(ctx, req.KID)
		return &AuthResponse{
			Token: token,
			Err:   err,
		}, err
	}
}

// Failed implements Failer.
func (r AuthResponse) Failed() error {
	return r.Err
}

// RegisterRequest collects the request parameters for the Register method.
type RegisterRequest struct {
	KID  string               `json:"kid"`
	Opts *service.KeysOptions `json:"opts"`
}

// RegisterResponse collects the response parameters for the Register method.
type RegisterResponse struct {
	KID  string            `json:"kid"`
	Keys *jwtis.SigEncKeys `json:"keys"`
	Err  error             `json:"err"`
}

// MakeRegisterEndpoint returns an endpoint that invokes Register on the service.
func MakeRegisterEndpoint(s service.JWTISService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(*RegisterRequest)
		keys, err := s.Register(ctx, req.KID, req.Opts)
		return &RegisterResponse{
			KID:  req.KID,
			Keys: keys,
			Err:  err,
		}, err
	}
}

// Failed implements Failer.
func (r RegisterResponse) Failed() error {
	return r.Err
}

// UpdateKeysRequest collects the request parameters for the UpdateKeys method.
type UpdateKeysRequest struct {
	KID  string               `json:"kid"`
	Opts *service.KeysOptions `json:"opts"`
}

// UpdateKeysResponse collects the response parameters for the UpdateKeys method.
type UpdateKeysResponse struct {
	Keys *jwtis.SigEncKeys `json:"keys"`
	Err  error             `json:"err"`
}

// MakeUpdateKeysEndpoint returns an endpoint that invokes UpdateKeys on the service.
func MakeUpdateKeysEndpoint(s service.JWTISService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(*UpdateKeysRequest)
		keys, err := s.UpdateKeys(ctx, req.KID, req.Opts)
		return &UpdateKeysResponse{
			Err:  err,
			Keys: keys,
		}, err
	}
}

// Failed implements Failer.
func (r UpdateKeysResponse) Failed() error {
	return r.Err
}

// ListKeysRequest collects the request parameters for the ListKeys method.
type ListKeysRequest struct{}

// ListKeysResponse collects the response parameters for the ListKeys method.
type ListKeysResponse struct {
	KeysList []jwtis.KeysInfoSet `json:"keys_list"`
	Err      error               `json:"err"`
}

// MakeListKeysEndpoint returns an endpoint that invokes ListKeys on the service.
func MakeListKeysEndpoint(s service.JWTISService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		keysList, err := s.ListKeys(ctx)
		return &ListKeysResponse{
			Err:      err,
			KeysList: keysList,
		}, err
	}
}

// Failed implements Failer.
func (r ListKeysResponse) Failed() error {
	return r.Err
}

// DelKeysRequest collects the request parameters for the DelKeys method.
type DelKeysRequest struct {
	KID string `json:"kid"`
}

// DelKeysResponse collects the response parameters for the DelKeys method.
type DelKeysResponse struct {
	Err error `json:"err"`
}

// MakeDelKeysEndpoint returns an endpoint that invokes DelKeys on the service.
func MakeDelKeysEndpoint(s service.JWTISService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(*DelKeysRequest)
		err := s.DelKeys(ctx, req.KID)
		return &DelKeysResponse{Err: err}, err
	}
}

// Failed implements Failer.
func (r DelKeysResponse) Failed() error {
	return r.Err
}

// PublicKeysRequest collects the request parameters for the PublicKeys method.
type PublicKeysRequest struct {
	KID string `json:"kid"`
}

// PublicKeysResponse collects the response parameters for the PublicKeys method.
type PublicKeysResponse struct {
	Keys *jwtis.SigEncKeys `json:"keys"`
	Err  error             `json:"err"`
}

// MakePublicKeysEndpoint returns an endpoint that invokes PublicKeys on the service.
func MakePublicKeysEndpoint(s service.JWTISService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(*PublicKeysRequest)
		keys, err := s.PublicKeys(ctx, req.KID)
		return &PublicKeysResponse{
			Err:  err,
			Keys: keys,
		}, err
	}
}

// Failed implements Failer.
func (r PublicKeysResponse) Failed() error {
	return r.Err
}

// Failure is an interface that should be implemented by response types.
// Response encoders can check if responses are Failer, and if so they've
// failed, and if so encode them using a separate write path based on the error.
type Failure interface {
	Failed() error
}

// NewJWT implements Service. Primarily useful in a client.
func (e Endpoints) NewJWT(ctx context.Context, kid string, claims map[string]interface{}) (pair *service.JWTPair, err error) {
	request := &NewJWTRequest{
		KID:    kid,
		Claims: claims,
	}
	response, err := e.NewJWTEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(*NewJWTResponse).Pair, response.(*NewJWTResponse).Err
}

// RenewJWT implements Service. Primarily useful in a client.
func (e Endpoints) RenewJWT(ctx context.Context, kid string, refreshToken string, refreshStrategy string) (pair *service.JWTPair, err error) {
	request := &RenewJWTRequest{
		KID:             kid,
		RefreshToken:    refreshToken,
		RefreshStrategy: refreshStrategy,
	}
	response, err := e.RenewJWTEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(*RenewJWTResponse).Pair, response.(*RenewJWTResponse).Err
}

// RevokeJWT implements Service. Primarily useful in a client.
func (e Endpoints) RevokeJWT(ctx context.Context, kid string, jwtID string, refreshToken string) (err error) {
	request := &RevokeJWTRequest{
		KID:          kid,
		JwtID:        jwtID,
		RefreshToken: refreshToken,
	}
	response, err := e.RevokeJWTEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(*RevokeJWTResponse).Err
}

// Auth implements Service. Primarily useful in a client.
func (e Endpoints) Auth(ctx context.Context, kid string) (token string, err error) {
	request := &AuthRequest{KID: kid}
	response, err := e.AuthEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(*AuthResponse).Token, response.(*AuthResponse).Err
}

// Register implements Service. Primarily useful in a client.
func (e Endpoints) Register(ctx context.Context, kid string, opts *service.KeysOptions) (keys *jwtis.SigEncKeys, err error) {
	request := &RegisterRequest{
		KID:  kid,
		Opts: opts,
	}
	response, err := e.RegisterEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(*RegisterResponse).Keys, response.(*RegisterResponse).Err
}

// UpdateKeys implements Service. Primarily useful in a client.
func (e Endpoints) UpdateKeys(ctx context.Context, kid string, opts *service.KeysOptions) (keys *jwtis.SigEncKeys, err error) {
	request := &UpdateKeysRequest{
		KID:  kid,
		Opts: opts,
	}
	response, err := e.UpdateKeysEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(*UpdateKeysResponse).Keys, response.(*UpdateKeysResponse).Err
}

// ListKeys implements Service. Primarily useful in a client.
func (e Endpoints) ListKeys(ctx context.Context) (keysList []jwtis.KeysInfoSet, err error) {
	request := &ListKeysRequest{}
	response, err := e.ListKeysEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(*ListKeysResponse).KeysList, response.(*ListKeysResponse).Err
}

// DelKeys implements Service. Primarily useful in a client.
func (e Endpoints) DelKeys(ctx context.Context, kid string) (err error) {
	request := &DelKeysRequest{KID: kid}
	response, err := e.DelKeysEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(*DelKeysResponse).Err
}

// PublicKeys implements Service. Primarily useful in a client.
func (e Endpoints) PublicKeys(ctx context.Context, kid string) (keys *jwtis.SigEncKeys, err error) {
	request := &PublicKeysRequest{KID: kid}
	response, err := e.PublicKeysEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(*PublicKeysResponse).Keys, response.(*PublicKeysResponse).Err
}
