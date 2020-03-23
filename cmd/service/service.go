package service

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	endpoint1 "github.com/go-kit/kit/endpoint"
	log "github.com/go-kit/kit/log"
	prometheus "github.com/go-kit/kit/metrics/prometheus"
	"github.com/karantin2020/jwtis"
	endpoint "github.com/karantin2020/jwtis/pkg/endpoint"
	grpc "github.com/karantin2020/jwtis/pkg/grpc"
	pb "github.com/karantin2020/jwtis/pkg/grpc/pb"
	service "github.com/karantin2020/jwtis/pkg/service"
	group "github.com/oklog/run"
	prometheus1 "github.com/prometheus/client_golang/prometheus"
	promhttp "github.com/prometheus/client_golang/prometheus/promhttp"
	grpc1 "google.golang.org/grpc"
	jose "gopkg.in/square/go-jose.v2"
)

var logger log.Logger

// Define our flags. Your service probably won't need to bind listeners for
// all* supported transports, but we do it here for demonstration purposes.
var fs = flag.NewFlagSet("jwtis", flag.ExitOnError)
var debugAddr = fs.String("debug.addr", ":8080", "Debug and metrics listen address")
var grpcAddr = fs.String("grpc-addr", ":8082", "gRPC listen address")

// Run starts server process
func Run() {
	fs.Parse(os.Args[1:])

	// Create a single logger, which we'll use and give to other components.
	logger = log.NewLogfmtLogger(os.Stderr)
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

	var (
		keysRepo = &jwtis.KeysRepository{}
		contEnc  = jose.A128GCM
	)
	svc := service.New(keysRepo, contEnc, getServiceMiddleware(logger))
	eps := endpoint.New(svc, getEndpointMiddleware(logger))
	g := createService(eps)
	initMetricsEndpoint(g)
	initCancelInterrupt(g)
	logger.Log("exit", g.Run())
}

// RunServer starts server process
func RunServer(
	debugAddrP string,
	grpcAddrP string,
	keysRepo *jwtis.KeysRepository,
	contEnc jose.ContentEncryption,
) {
	logger = log.NewLogfmtLogger(os.Stderr)
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)
	*debugAddr = debugAddrP
	*grpcAddr = grpcAddrP

	svc := service.New(keysRepo, contEnc, getServiceMiddleware(logger))
	eps := endpoint.New(svc, getEndpointMiddleware(logger))
	g := createService(eps)
	initMetricsEndpoint(g)
	initCancelInterrupt(g)
	logger.Log("exit", g.Run())

}
func initGRPCHandler(endpoints endpoint.Endpoints, g *group.Group) {
	options := defaultGRPCOptions(logger)
	// Add your GRPC options here

	grpcServer := grpc.NewGRPCServer(endpoints, options)
	grpcListener, err := net.Listen("tcp", *grpcAddr)
	if err != nil {
		logger.Log("transport", "gRPC", "during", "Listen", "err", err)
	}
	g.Add(func() error {
		logger.Log("transport", "gRPC", "addr", *grpcAddr)
		baseServer := grpc1.NewServer()
		pb.RegisterJWTISServiceServer(baseServer, grpcServer)
		return baseServer.Serve(grpcListener)
	}, func(error) {
		grpcListener.Close()
	})

}
func getServiceMiddleware(logger log.Logger) (mw []service.Middleware) {
	mw = []service.Middleware{}
	mw = addDefaultServiceMiddleware(logger, mw)
	// Append your middleware here

	return
}
func getEndpointMiddleware(logger log.Logger) (mw map[string][]endpoint1.Middleware) {
	mw = map[string][]endpoint1.Middleware{}
	duration := prometheus.NewSummaryFrom(prometheus1.SummaryOpts{
		Help:      "Request duration in seconds.",
		Name:      "request_duration_seconds",
		Namespace: "jwtis",
		Subsystem: "grpc_transport",
	}, []string{"method", "success"})
	addDefaultEndpointMiddleware(logger, duration, mw)
	// Add you endpoint middleware here

	return
}
func initMetricsEndpoint(g *group.Group) {
	http.DefaultServeMux.Handle("/metrics", promhttp.Handler())
	debugListener, err := net.Listen("tcp", *debugAddr)
	if err != nil {
		logger.Log("transport", "debug/HTTP", "during", "Listen", "err", err)
	}
	g.Add(func() error {
		logger.Log("transport", "debug/HTTP", "addr", *debugAddr)
		return http.Serve(debugListener, http.DefaultServeMux)
	}, func(error) {
		debugListener.Close()
	})
}
func initCancelInterrupt(g *group.Group) {
	cancelInterrupt := make(chan struct{})
	g.Add(func() error {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		select {
		case sig := <-c:
			return fmt.Errorf("received signal %s", sig)
		case <-cancelInterrupt:
			return nil
		}
	}, func(error) {
		close(cancelInterrupt)
	})
}
