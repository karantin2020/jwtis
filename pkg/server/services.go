package server

import (
	"context"

	"github.com/karantin2020/jwtis/pkg/errdef"
	"github.com/karantin2020/jwtis/pkg/services"
	"github.com/karantin2020/jwtis/pkg/services/healthcheck"
	"github.com/karantin2020/jwtis/pkg/services/keys"
	"github.com/karantin2020/jwtis/pkg/services/version"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func initServices(ctx context.Context) error {
	init, err := services.FromContext(ctx)
	if err != nil {
		return errors.Wrap(errdef.ErrInternal, "server: error init services: "+err.Error())
	}
	init.Lock()
	defer init.Unlock()

	// Register all services in *services.InitContext
	init.ServiceInfos = append(init.ServiceInfos,
		version.Register(),
		healthcheck.Register(),
		keys.Register(),
	)

	for i := range init.ServiceInfos {
		logger.Info("init service", zap.String("service", init.ServiceInfos[i].ID))
		srv, err := init.ServiceInfos[i].InitFn(ctx)
		if err != nil {
			return errors.Wrapf(errdef.ErrInternal, "server: error init service '%s': %s",
				init.ServiceInfos[i].ID, err.Error())
		}
		init.Services[init.ServiceInfos[i].ID] = srv
		// Add all grpc services into init.GrpcRegisterers
		if init.ServiceInfos[i].Type == services.GRPCService {
			logger.Info("register grpc service", zap.String("service", init.ServiceInfos[i].ID))
			regSrv, ok := srv.(services.GRPCRegisterer)
			if !ok {
				return errors.Wrap(errdef.ErrInternal, "server: invalid grpc type defined for"+
					" service "+init.ServiceInfos[i].ID)
			}
			init.GrpcRegisterers = append(init.GrpcRegisterers, regSrv)
		}
	}
	return nil
}
