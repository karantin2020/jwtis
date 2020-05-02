package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/soheilhy/cmux"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/karantin2020/jwtis/pkg/errdef"
	"github.com/karantin2020/jwtis/pkg/services"
	"github.com/karantin2020/jwtis/pkg/services/healthcheck"
	promhttp "github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

const (
	system = "" // empty string represents the health of the system
)

// Server holds server info
type Server struct {
	grpcServer     *grpc.Server
	metricsServer  *http.Server
	cmux           cmux.CMux
	serverConn     net.Listener
	serverConnGRPC net.Listener
	serverConnHTTP net.Listener
	logger         *zap.Logger
	init           *services.InitContext
	grpcServices   []services.GRPCRegisterer
}

var logger *zap.Logger

// New constructs new server
func New(ctx context.Context) (*Server, error) {
	init, err := services.FromContext(ctx)
	if err != nil {
		return nil, errors.Wrap(errdef.ErrInternal, "server: create new server error: "+err.Error())
	}
	// options := defaultGRPCOptions(logger)
	// Add your GRPC options here
	logger = init.Logger.With(zap.String("component", "server"))
	panicFunc := func(p interface{}) (err error) {
		logger := logger.With(zap.String("operation", "grpc_recovery"))
		logger.Error("panic", zap.Any("cause", p))
		close(init.CancelInterrupt)
		return nil
	}
	logger.Info("init services", zap.String("operation", "initServices"), zap.String("status", "started"))
	err = initServices(ctx)
	if err != nil {
		return nil, errors.Wrap(errdef.ErrInternal, "server: init services error: "+err.Error())
	}
	logger.Info("init services", zap.String("operation", "initServices"), zap.String("status", "finished"))
	// Shared options for the logger, with a custom gRPC code to log level function.
	recoveryOpts := []grpc_recovery.Option{
		grpc_recovery.WithRecoveryHandler(panicFunc),
	}
	logOpts := []grpc_zap.Option{
		grpc_zap.WithDecider(func(fullMethodName string, err error) bool {
			// will not log gRPC calls if it was a call to healthcheck and no error was raised
			if fullMethodName == "/grpc.health.v1.Health/Check" ||
				fullMethodName == "/grpc.health.v1.Health/Watch" {
				return false
			}

			// by default everything will be logged
			return true
		}),
		grpc_zap.WithDurationField(func(duration time.Duration) zapcore.Field {
			return zap.Int64("grpc.time_us", duration.Nanoseconds()/1000)
		}),
	}
	grpcLogger := logger.With(zap.String("transport", "grpc"))
	serverOptions := []grpc.ServerOption{
		grpc_middleware.WithUnaryServerChain(
			grpc_prometheus.UnaryServerInterceptor,
			grpc_recovery.UnaryServerInterceptor(recoveryOpts...),
			grpc_zap.UnaryServerInterceptor(grpcLogger, logOpts...),
		),
		grpc_middleware.WithStreamServerChain(
			grpc_prometheus.StreamServerInterceptor,
			grpc_recovery.StreamServerInterceptor(recoveryOpts...),
			grpc_zap.StreamServerInterceptor(grpcLogger, logOpts...),
		),
	}
	if init.MaxRecvMsgSize > 0 {
		serverOptions = append(serverOptions, grpc.MaxRecvMsgSize(init.MaxRecvMsgSize))
	}
	if init.MaxSendMsgSize > 0 {
		serverOptions = append(serverOptions, grpc.MaxSendMsgSize(init.MaxSendMsgSize))
	}
	grpcServer := grpc.NewServer(serverOptions...)
	serverConn, err := net.Listen("tcp", init.Address)
	if err != nil {
		return nil, errors.Wrap(errdef.ErrInternal, "server: failed to get listener for grpc: "+err.Error())
	}
	var serverConnHTTP net.Listener
	var serverConnGRPC net.Listener
	var m cmux.CMux
	if !init.DisableMetrics {
		if init.MetricsAddr == "" || init.Address == init.MetricsAddr {
			// Create a cmux
			m = cmux.New(serverConn)
			serverConnGRPC = m.MatchWithWriters(cmux.HTTP2MatchHeaderFieldSendSettings("content-type", "application/grpc"))
			serverConnHTTP = m.Match(cmux.Any())
			// serverConnGRPC = m.Match(cmux.HTTP2() /*("content-type", "application/grpc")*/)
			// serverConnHTTP = m.Match(cmux.HTTP1Fast())
		} else {
			serverConnHTTP, err = net.Listen("tcp", init.MetricsAddr)
			if err != nil {
				return nil, errors.Wrap(errdef.ErrInternal, "server: failed to get listener for metrics handler")
			}
		}
	}

	s := &Server{
		grpcServer:     grpcServer,
		metricsServer:  nil,
		cmux:           m,
		serverConn:     serverConn,
		serverConnGRPC: serverConnGRPC,
		serverConnHTTP: serverConnHTTP,
		logger:         logger,
		init:           init,
		grpcServices:   init.GrpcRegisterers,
	}
	return s, nil
}

// ServeGRPC starts grpc server process
func (s *Server) ServeGRPC() {
	s.init.G.Add(func() error {
		logger := s.logger.With(zap.String("transport", "grpc"))
		grpc_zap.ReplaceGrpcLoggerV2(logger)
		for i := range s.grpcServices {
			s.grpcServices[i].RegisterGRPC(s.grpcServer)
		}
		if s.init.GRPCHistogram {
			// enable grpc time histograms to measure rpc latencies
			grpc_prometheus.EnableHandlingTimeHistogram()
		}
		// before we start serving the grpc API register the grpc_prometheus metrics
		// handler.  This needs to be the last service registered so that it can collect
		// metrics for every other service
		grpc_prometheus.Register(s.grpcServer)
		// Register reflection service on gRPC server.
		reflection.Register(s.grpcServer)
		health, err := healthcheck.FromInitContext(s.init)
		if err != nil {
			fmt.Println("server: healthcheck service is not found: " + err.Error())
			return errors.Wrap(errdef.ErrInternal, "server: healthcheck service is not found: "+err.Error())
		}
		health.SetServingStatus(system, healthpb.HealthCheckResponse_SERVING)
		logger.Info("start grpc server", zap.String("addr", s.init.Address))
		return s.grpcServer.Serve(s.serverConnGRPC)
	}, func(error) {
		health, err := healthcheck.FromInitContext(s.init)
		if err == nil {
			health.SetServingStatus(system, healthpb.HealthCheckResponse_NOT_SERVING)
		}
		s.grpcServer.GracefulStop()
		s.logger.Info("graceful stop grpc server", zap.String("transport", "grpc"))
	})
	s.init.G.Add(func() error {
		s.logger.Debug("serve cmux", zap.String("listener", "cmux"))
		return s.cmux.Serve()
	}, func(error) {
		s.logger.Debug("close listener", zap.String("listener", "cmux"))
	})
}

// ServeMetrics provides a prometheus endpoint for exposing metrics
func (s *Server) ServeMetrics() {
	if s.init.DisableMetrics {
		return
	}
	s.init.G.Add(func() error {
		s.logger.Info("start metrics server", zap.String("transport", "http"),
			zap.String("addr", s.init.Address+"/v1/metrics"))
		m := http.NewServeMux()
		m.Handle("/v1/metrics", promhttp.Handler())
		s.metricsServer = &http.Server{Handler: m}
		return http.Serve(s.serverConnHTTP, m)
	}, func(error) {
		s.metricsServer.Shutdown(context.Background())
		s.logger.Info("graceful shutdown metrics server", zap.String("transport", "http"))
	})
}
