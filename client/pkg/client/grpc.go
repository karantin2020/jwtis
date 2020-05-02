package client

import (
	"strings"
	"time"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"

	// import health client for health check function
	_ "google.golang.org/grpc/health"
)

const (
	// DefaultMaxRecvMsgSize defines the default maximum message size for
	// receiving protobufs passed over the GRPC API.
	DefaultMaxRecvMsgSize = 16 << 20
	// DefaultMaxSendMsgSize defines the default maximum message size for
	// sending protobufs passed over the GRPC API.
	DefaultMaxSendMsgSize = 16 << 20
)

var (
	// ErrConnRefused describes connection refused error
	ErrConnRefused = errors.New("failed to dial server: connection refused")
)

// newConnection returns configured client connection
func newConnection(addr string, copts []grpc.DialOption) (*grpc.ClientConn, error) {
	backoffConfig := backoff.DefaultConfig
	backoffConfig.MaxDelay = 2 * time.Second
	connParams := grpc.ConnectParams{
		Backoff: backoffConfig,
	}
	var serviceConfig = `{
		"loadBalancingPolicy": "round_robin",
		"healthCheckConfig": {
			"serviceName": ""
		}
	}`

	gopts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithInsecure(),
		grpc.FailOnNonTempDialError(true),
		grpc.WithConnectParams(connParams),
		grpc.WithDefaultServiceConfig(serviceConfig),

		// TODO: may need to allow configuration of this on the client.
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(DefaultMaxRecvMsgSize)),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(DefaultMaxSendMsgSize)),
	}
	gopts = append(gopts, copts...)

	// ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	// defer cancel()
	conn, err := grpc.Dial(addr, gopts...)
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			return nil, ErrConnRefused
		}
		return nil, errors.Wrap(err, "failed to dial server")
	}
	return conn, nil
}
