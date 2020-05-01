package healthcheck

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/karantin2020/jwtis/pkg/errdef"
	"github.com/karantin2020/jwtis/pkg/services"
	"github.com/pkg/errors"
)

var _ HealthServer = &service{}

type service struct {
	*health.Server
}

// HealthServer interface
type HealthServer interface {
	Check(ctx context.Context, in *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error)
	Watch(in *healthpb.HealthCheckRequest, stream healthgrpc.Health_WatchServer) error
	SetServingStatus(service string, servingStatus healthpb.HealthCheckResponse_ServingStatus)
	Shutdown()
	Resume()
}

func newService() *service {
	return &service{
		health.NewServer(),
	}
}

// Register func registers healthCheck service
func Register() *services.ServiceInfo {
	return &services.ServiceInfo{
		Type: services.GRPCService,
		ID:   services.Healthcheck,
		InitFn: func(ctx context.Context) (interface{}, error) {
			svc := newService()
			return svc, nil
		},
	}
}

// FromContext returns grpc_health_v1.HealthServer from service init context
// wrapped in context.Context
func FromContext(ctx context.Context) (HealthServer, error) {
	svcCtx, err := services.FromContext(ctx)
	if err != nil {
		return nil, errors.Wrap(errdef.ErrInternal, "healthcheck: service context is not found: "+err.Error())
	}
	return FromInitContext(svcCtx)
}

// FromInitContext returns HealthServer from service init context
func FromInitContext(init *services.InitContext) (HealthServer, error) {
	init.RLock()
	defer init.RUnlock()
	s, ok := init.Services[services.Healthcheck]
	if !ok {
		return nil, errors.Wrap(errdef.ErrInternal, "healthcheck: healthcheck service is not found in context")
	}
	sh, ok := s.(HealthServer)
	if !ok {
		return nil, errors.Wrap(errdef.ErrInternal, "healthcheck: service in context is not of type HealthServer")
	}
	return sh, nil
}

func (s *service) RegisterGRPC(server *grpc.Server) error {
	healthpb.RegisterHealthServer(server, s)
	return nil
}
