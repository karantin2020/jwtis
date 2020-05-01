package client

import (
	"context"

	empty "github.com/golang/protobuf/ptypes/empty"
	apiVersion "github.com/karantin2020/jwtis/api/version/v1"
	"google.golang.org/grpc"
)

// Client is the client to interact with jwtis and its various services
// using a uniform interface
type Client interface {
	Version() (*apiVersion.VersionResponse, error)
}

// New returns configured client
func New(addr string, copts ...grpc.DialOption) (Client, error) {
	cl := &clientImpl{}
	conn, err := newConnection(addr, copts)
	if err != nil {
		return nil, err
	}
	cl.versionClient = apiVersion.NewVersionClient(conn)
	return cl, nil
}

type clientImpl struct {
	conn          *grpc.ClientConn
	versionClient apiVersion.VersionClient
}

func (c *clientImpl) Version() (*apiVersion.VersionResponse, error) {
	return c.versionClient.Version(context.Background(), &empty.Empty{})
}
