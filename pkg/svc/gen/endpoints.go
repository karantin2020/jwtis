package gen

import (
	"context"
	"fmt"
	"time"

	"github.com/go-kit/kit/endpoint"
	log "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

// Endpoints struct holds gokit endpoints
type Endpoints struct {
	NewJWTEndpoint     endpoint.Endpoint
	RenewJWTEndpoint   endpoint.Endpoint
	RevokeJWTEndpoint  endpoint.Endpoint
	AuthEndpoint       endpoint.Endpoint
	RegisterEndpoint   endpoint.Endpoint
	UpdateKeysEndpoint endpoint.Endpoint
	ListKeysEndpoint   endpoint.Endpoint // half duplex
	DelKeysEndpoint    endpoint.Endpoint
	PublicKeysEndpoint endpoint.Endpoint
	PingEndpoint       endpoint.Endpoint
	ReadyEndpoint      endpoint.Endpoint
}

// WithLogging adds logging middleware
func (e *Endpoints) WithLogging(logger log.Logger) {
	e.NewJWTEndpoint = LoggingMiddleware(logger, "NewJWTEndpoint")(e.NewJWTEndpoint)
	e.RenewJWTEndpoint = LoggingMiddleware(logger, "RenewJWTEndpoint")(e.RenewJWTEndpoint)
	e.RevokeJWTEndpoint = LoggingMiddleware(logger, "RevokeJWTEndpoint")(e.RevokeJWTEndpoint)
	e.AuthEndpoint = LoggingMiddleware(logger, "AuthEndpoint")(e.AuthEndpoint)
	e.RegisterEndpoint = LoggingMiddleware(logger, "RegisterEndpoint")(e.RegisterEndpoint)
	e.UpdateKeysEndpoint = LoggingMiddleware(logger, "UpdateKeysEndpoint")(e.UpdateKeysEndpoint)
	e.ListKeysEndpoint = LoggingMiddleware(logger, "ListKeysEndpoint")(e.ListKeysEndpoint)
	e.DelKeysEndpoint = LoggingMiddleware(logger, "DelKeysEndpoint")(e.DelKeysEndpoint)
	e.PublicKeysEndpoint = LoggingMiddleware(logger, "PublicKeysEndpoint")(e.PublicKeysEndpoint)
	e.PingEndpoint = LoggingMiddleware(logger, "PingEndpoint")(e.PingEndpoint)
	e.ReadyEndpoint = LoggingMiddleware(logger, "ReadyEndpoint")(e.ReadyEndpoint)
}

func wrapEndpoint(ep endpoint.Endpoint, mwares []endpoint.Middleware) endpoint.Endpoint {
	for i := range mwares {
		ep = mwares[i](ep)
	}
	return ep
}

// MakeEndpoints constructor
func MakeEndpoints(svc Service, mwares []endpoint.Middleware) Endpoints {
	return Endpoints{
		NewJWTEndpoint:     wrapEndpoint(makeNewJWTEndpoint(svc), mwares),
		RenewJWTEndpoint:   wrapEndpoint(makeRenewJWTEndpoint(svc), mwares),
		RevokeJWTEndpoint:  wrapEndpoint(makeRevokeJWTEndpoint(svc), mwares),
		AuthEndpoint:       wrapEndpoint(makeAuthEndpoint(svc), mwares),
		RegisterEndpoint:   wrapEndpoint(makeRegisterEndpoint(svc), mwares),
		UpdateKeysEndpoint: wrapEndpoint(makeUpdateKeysEndpoint(svc), mwares),
		ListKeysEndpoint:   wrapEndpoint(makeListKeysEndpoint(svc), mwares),
		DelKeysEndpoint:    wrapEndpoint(makeDelKeysEndpoint(svc), mwares),
		PublicKeysEndpoint: wrapEndpoint(makePublicKeysEndpoint(svc), mwares),
		PingEndpoint:       wrapEndpoint(makePingEndpoint(svc), mwares),
		ReadyEndpoint:      wrapEndpoint(makeReadyEndpoint(svc), mwares),
	}
}
func makeNewJWTEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		domReq, ok := req.(*NewJWTRequest)
		if !ok {
			err := fmt.Errorf("expecting *NewJWTRequest received %T", req)
			level.Error(svc.Log()).Log("endpoint_error", err)
			return nil, err
		}
		resp, err := svc.NewJWT(ctx, domReq)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}
}

func makeRenewJWTEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		domReq, ok := req.(*RenewJWTRequest)
		if !ok {
			err := fmt.Errorf("expecting *RenewJWTRequest received %T", req)
			level.Error(svc.Log()).Log("endpoint_error", err)
			return nil, err
		}
		resp, err := svc.RenewJWT(ctx, domReq)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}
}

func makeRevokeJWTEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		domReq, ok := req.(*RevokeJWTRequest)
		if !ok {
			err := fmt.Errorf("expecting *RevokeJWTRequest received %T", req)
			level.Error(svc.Log()).Log("endpoint_error", err)
			return nil, err
		}
		resp, err := svc.RevokeJWT(ctx, domReq)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}
}

func makeAuthEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		domReq, ok := req.(*AuthRequest)
		if !ok {
			err := fmt.Errorf("expecting *AuthRequest received %T", req)
			level.Error(svc.Log()).Log("endpoint_error", err)
			return nil, err
		}
		resp, err := svc.Auth(ctx, domReq)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}
}

func makeRegisterEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		domReq, ok := req.(*RegisterRequest)
		if !ok {
			err := fmt.Errorf("expecting *RegisterRequest received %T", req)
			level.Error(svc.Log()).Log("endpoint_error", err)
			return nil, err
		}
		resp, err := svc.Register(ctx, domReq)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}
}

func makeUpdateKeysEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		domReq, ok := req.(*UpdateKeysRequest)
		if !ok {
			err := fmt.Errorf("expecting *UpdateKeysRequest received %T", req)
			level.Error(svc.Log()).Log("endpoint_error", err)
			return nil, err
		}
		resp, err := svc.UpdateKeys(ctx, domReq)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}
}

// half duplex
func makeListKeysEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		reqAndStream, ok := req.(*RequestAndStreamListKeys)
		if !ok {
			err := fmt.Errorf("expecting *RequestAndStreamListKeys received %T", req)
			level.Error(svc.Log()).Log("endpoint_error", err)
			return nil, err
		}
		err := svc.ListKeys(reqAndStream.Request, reqAndStream.Stream)
		if err != nil {
			return nil, err
		}
		return nil, nil
	}
}

func makeDelKeysEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		domReq, ok := req.(*DelKeysRequest)
		if !ok {
			err := fmt.Errorf("expecting *DelKeysRequest received %T", req)
			level.Error(svc.Log()).Log("endpoint_error", err)
			return nil, err
		}
		resp, err := svc.DelKeys(ctx, domReq)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}
}

func makePublicKeysEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		domReq, ok := req.(*PublicKeysRequest)
		if !ok {
			err := fmt.Errorf("expecting *PublicKeysRequest received %T", req)
			level.Error(svc.Log()).Log("endpoint_error", err)
			return nil, err
		}
		resp, err := svc.PublicKeys(ctx, domReq)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}
}

func makePingEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		domReq, ok := req.(*PingRequest)
		if !ok {
			err := fmt.Errorf("expecting *PingRequest received %T", req)
			level.Error(svc.Log()).Log("endpoint_error", err)
			return nil, err
		}
		resp, err := svc.Ping(ctx, domReq)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}
}

func makeReadyEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		domReq, ok := req.(*ReadyRequest)
		if !ok {
			err := fmt.Errorf("expecting *ReadyRequest received %T", req)
			level.Error(svc.Log()).Log("endpoint_error", err)
			return nil, err
		}
		resp, err := svc.Ready(ctx, domReq)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}
}

// LoggingMiddleware returns an endpoint middleware that logs the
// duration of each invocation, and the resulting error, if any.
func LoggingMiddleware(logger log.Logger, methodName string) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		logger = log.With(logger, "method", methodName)
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			defer func(begin time.Time) {
				logger.Log("transport_error", err, "took", time.Since(begin))
			}(time.Now())
			return next(ctx, request)
		}
	}
}
