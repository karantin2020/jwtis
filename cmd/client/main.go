package main

import (
	"context"
	"fmt"
	"os"

	"google.golang.org/grpc"

	kitJWT "github.com/go-kit/kit/auth/jwt"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	kitGRPC "github.com/go-kit/kit/transport/grpc"
	"github.com/karantin2020/jwtis/svc/gen"
)

var grpcHostAndPort = "127.0.0.1:40430"

func main() {
	logger := log.NewLogfmtLogger(os.Stdout)
	logger = log.With(logger, "caller", log.Caller(4))
	logger = level.NewFilter(logger, level.AllowDebug())

	conn, err := grpc.Dial(grpcHostAndPort, grpc.WithInsecure())
	if err != nil {
		level.Error(logger).Log("error", "unable to Dial")
		os.Exit(1)
	}

	clientOptions := []kitGRPC.ClientOption{kitGRPC.ClientBefore(kitJWT.ContextToGRPC())}
	cl := gen.NewClient(conn, logger, clientOptions...)
	ctx := context.Background()
	testkid := "testkid1"
	cl.DelKeys(ctx, &gen.DelKeysRequest{KID: testkid})
	// if err != nil {
	// 	level.Error(logger).Log("unable to Delete", err)
	// 	os.Exit(1)
	// }
	resp, err := cl.Register(ctx, &gen.RegisterRequest{KID: testkid})
	if err != nil {
		level.Error(logger).Log("unable to Register", err)
		os.Exit(1)
	}
	level.Error(logger).Log("respRegister", fmt.Sprintf("%#v", resp))
	resp1, err := cl.NewJWT(ctx, &gen.NewJWTRequest{KID: testkid})
	if err != nil {
		level.Error(logger).Log("unable to Register", err)
		os.Exit(1)
	}
	level.Error(logger).Log("respNewJWT", fmt.Sprintf("%#v", resp1))
}
