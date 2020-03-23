package service

import (
	endpoint1 "github.com/go-kit/kit/endpoint"
	log "github.com/go-kit/kit/log"
	prometheus "github.com/go-kit/kit/metrics/prometheus"
	grpc "github.com/go-kit/kit/transport/grpc"
	endpoint "github.com/karantin2020/jwtis/pkg/endpoint"
	service "github.com/karantin2020/jwtis/pkg/service"
	group "github.com/oklog/run"
)

func createService(endpoints endpoint.Endpoints) (g *group.Group) {
	g = &group.Group{}
	initGRPCHandler(endpoints, g)
	return g
}
func defaultGRPCOptions(logger log.Logger) map[string][]grpc.ServerOption {
	options := map[string][]grpc.ServerOption{
		"Auth": {
			grpc.ServerErrorLogger(logger),
			// grpc.ServerBefore(),
		},
		"DelKeys": {
			grpc.ServerErrorLogger(logger),
			// grpc.ServerBefore(),
		},
		"ListKeys": {
			grpc.ServerErrorLogger(logger),
			// grpc.ServerBefore(),
		},
		"NewJWT": {
			grpc.ServerErrorLogger(logger),
			// grpc.ServerBefore(),
		},
		"PublicKeys": {
			grpc.ServerErrorLogger(logger),
			// grpc.ServerBefore(),
		},
		"Register": {
			grpc.ServerErrorLogger(logger),
			// grpc.ServerBefore(),
		},
		"RenewJWT": {
			grpc.ServerErrorLogger(logger),
			// grpc.ServerBefore(),
		},
		"RevokeJWT": {
			grpc.ServerErrorLogger(logger),
			// grpc.ServerBefore(),
		},
		"UpdateKeys": {
			grpc.ServerErrorLogger(logger),
			// grpc.ServerBefore(),
		},
	}
	return options
}
func addDefaultEndpointMiddleware(logger log.Logger, duration *prometheus.Summary, mw map[string][]endpoint1.Middleware) {
	mw["NewJWT"] = []endpoint1.Middleware{
		endpoint.LoggingMiddleware(log.With(logger, "method", "NewJWT")),
		endpoint.InstrumentingMiddleware(duration.With("method", "NewJWT")),
	}
	mw["RenewJWT"] = []endpoint1.Middleware{
		endpoint.LoggingMiddleware(log.With(logger, "method", "RenewJWT")),
		endpoint.InstrumentingMiddleware(duration.With("method", "RenewJWT")),
	}
	mw["RevokeJWT"] = []endpoint1.Middleware{
		endpoint.LoggingMiddleware(log.With(logger, "method", "RevokeJWT")),
		endpoint.InstrumentingMiddleware(duration.With("method", "RevokeJWT")),
	}
	mw["Auth"] = []endpoint1.Middleware{
		endpoint.LoggingMiddleware(log.With(logger, "method", "Auth")),
		endpoint.InstrumentingMiddleware(duration.With("method", "Auth")),
	}
	mw["Register"] = []endpoint1.Middleware{
		endpoint.LoggingMiddleware(log.With(logger, "method", "Register")),
		endpoint.InstrumentingMiddleware(duration.With("method", "Register")),
	}
	mw["UpdateKeys"] = []endpoint1.Middleware{
		endpoint.LoggingMiddleware(log.With(logger, "method", "UpdateKeys")),
		endpoint.InstrumentingMiddleware(duration.With("method", "UpdateKeys")),
	}
	mw["ListKeys"] = []endpoint1.Middleware{
		endpoint.LoggingMiddleware(log.With(logger, "method", "ListKeys")),
		endpoint.InstrumentingMiddleware(duration.With("method", "ListKeys")),
	}
	mw["DelKeys"] = []endpoint1.Middleware{
		endpoint.LoggingMiddleware(log.With(logger, "method", "DelKeys")),
		endpoint.InstrumentingMiddleware(duration.With("method", "DelKeys")),
	}
	mw["PublicKeys"] = []endpoint1.Middleware{
		endpoint.LoggingMiddleware(log.With(logger, "method", "PublicKeys")),
		endpoint.InstrumentingMiddleware(duration.With("method", "PublicKeys")),
	}
}
func addDefaultServiceMiddleware(logger log.Logger, mw []service.Middleware) []service.Middleware {
	return append(mw, service.LoggingMiddleware(logger))
}
func addEndpointMiddlewareToAllMethods(mw map[string][]endpoint1.Middleware, m endpoint1.Middleware) {
	methods := []string{"NewJWT",
		"RenewJWT",
		"RevokeJWT",
		"Auth",
		"Register",
		"UpdateKeys",
		"ListKeys",
		"DelKeys",
		"PublicKeys",
	}
	for _, v := range methods {
		mw[v] = append(mw[v], m)
	}
}
