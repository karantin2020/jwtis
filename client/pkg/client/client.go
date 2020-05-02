package client

import (
	"context"

	empty "github.com/golang/protobuf/ptypes/empty"
	apiKeys "github.com/karantin2020/jwtis/api/keys/v1"
	apiVersion "github.com/karantin2020/jwtis/api/version/v1"
	keys "github.com/karantin2020/jwtis/pkg/services/keys"
	"google.golang.org/grpc"
)

// Client is the client to interact with jwtis and its various services
// using a uniform interface
type Client interface {
	VersionClient
	KeysClient
}

var _ Client = &clientImpl{}

// VersionClient is client interface to interact with version service
type VersionClient interface {
	Version() (*apiVersion.VersionResponse, error)
}

// KeysClient is client interface to interact with keys service
type KeysClient interface {
	Auth(ctx context.Context, in *keys.AuthRequest) (*keys.AuthResponse, error)
	Register(ctx context.Context, in *keys.RegisterRequest) (*keys.RegisterResponse, error)
	UpdateKeys(ctx context.Context, in *keys.UpdateKeysRequest) (*keys.UpdateKeysResponse, error)
	ListKeys(ctx context.Context, in *keys.ListKeysRequest) ([]*keys.ListKeysResponse, error)
	DelKeys(ctx context.Context, in *keys.DelKeysRequest) (*keys.DelKeysResponse, error)
	PublicKeys(ctx context.Context, in *keys.PublicKeysRequest) (*keys.PublicKeysResponse, error)
}

// New returns configured client
func New(addr string, copts ...grpc.DialOption) (Client, error) {
	cl := &clientImpl{}
	conn, err := newConnection(addr, copts)
	if err != nil {
		return nil, err
	}
	cl.versionClient = apiVersion.NewVersionClient(conn)
	cl.keysClient = apiKeys.NewKeysClient(conn)
	cl.ctx = context.Background()
	cl.callOpts = []grpc.CallOption{}
	return cl, nil
}

type clientImpl struct {
	conn          *grpc.ClientConn
	callOpts      []grpc.CallOption
	versionClient apiVersion.VersionClient
	keysClient    apiKeys.KeysClient
	ctx           context.Context
}

func (c *clientImpl) Version() (*apiVersion.VersionResponse, error) {
	return c.versionClient.Version(c.ctx, &empty.Empty{}, c.callOpts...)
}
