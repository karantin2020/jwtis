package version

import (
	"context"
	"runtime"

	empty "github.com/golang/protobuf/ptypes/empty"
	api "github.com/karantin2020/jwtis/api/version/v1"
	"github.com/karantin2020/jwtis/pkg/errdef"
	"github.com/karantin2020/jwtis/pkg/services"
	jversion "github.com/karantin2020/jwtis/version"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
)

var _ api.VersionServer = &service{}

// Register func registers version service
func Register() *services.ServiceInfo {
	return &services.ServiceInfo{
		Type: services.GRPCService,
		ID:   services.Version,
		InitFn: func(ctx context.Context) (interface{}, error) {
			svc := &service{
				checksum:  jversion.ExecutableChecksum(),
				goVersion: runtime.Version(),
			}
			return svc, nil
		},
	}
}

// FromContext returns initialized api.VersionServer from context wrapped in context.Context
func FromContext(ctx context.Context) (api.VersionServer, error) {
	init, err := services.FromContext(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "version: service context is not found")
	}
	return FromInitContext(init)
}

// FromInitContext returns initialized api.VersionServer from context
func FromInitContext(init *services.InitContext) (api.VersionServer, error) {
	init.RLock()
	defer init.RUnlock()
	vs, ok := init.Services[services.Version]
	if !ok {
		return nil, errors.Wrap(errdef.ErrInternal, "version: service not found in context")
	}
	svc, ok := vs.(api.VersionServer)
	if !ok {
		return nil, errors.Wrap(errdef.ErrInternal, "version: service in context is not type of api.VersionServer")
	}
	return svc, nil
}

type service struct {
	checksum  []byte
	goVersion string
}

func (s *service) RegisterGRPC(server *grpc.Server) error {
	api.RegisterVersionServer(server, s)
	return nil
}

func (s *service) Version(ctx context.Context, _ *empty.Empty) (*api.VersionResponse, error) {
	return &api.VersionResponse{
		Version:        jversion.AppVersion,
		Checksum:       s.checksum,
		LastCommitSHA:  jversion.LastCommitSHA,
		LastCommitTime: jversion.LastCommitTime,
		GitBranch:      jversion.GitBranch,
		BuildTime:      jversion.BuildTime,
		GoVersion:      s.goVersion,
	}, nil
}
