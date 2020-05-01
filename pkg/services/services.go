package services

import (
	"context"
	"sync"

	"github.com/karantin2020/jwtis/pkg/errdef"
	"github.com/karantin2020/jwtis/pkg/repos/keys"
	group "github.com/oklog/run"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	jose "gopkg.in/square/go-jose.v2"
)

const (
	// Healthcheck is healthcheck service
	Healthcheck = "healthcheck-service"
	// Version is healthcheck service
	Version = "version-service"
	// JWT is jwt issuer service
	JWT = "jwt-service"
	// Keys is keys interface service
	Keys = "keys-service"
)

// ServiceInfo contains information for registering service
type ServiceInfo struct {
	// Type of the plugin
	Type Type
	// ID of the plugin
	ID string
	// Config specific to the plugin
	Config interface{}
	// Requires is a list of plugins that the registered plugin requires to be available
	Requires []Type

	// InitFn is called when initializing a plugin. The registration and
	// context are passed in. The init function may modify the registration to
	// add exports, capabilities and platform support declarations.
	InitFn func(context.Context) (interface{}, error)
	// Disable the plugin from loading
	Disable bool
}

// GRPCRegisterer interface to register grpc services
type GRPCRegisterer interface {
	RegisterGRPC(server *grpc.Server) error
}

// Type is the type of the plugin
type Type string

func (t Type) String() string { return string(t) }

const (
	// InternalService implements an internal service
	InternalService Type = "jwtis.internal.v1"
	// GRPCService implements a grpc service
	GRPCService Type = "jwtis.grpc.v1"
)

// InitContext is used for service initialization
type InitContext struct {
	KeysRepo        *keys.Repository
	ContEnc         jose.ContentEncryption
	Logger          *zap.Logger
	G               *group.Group
	CancelInterrupt chan struct{}
	GrpcRegisterers []GRPCRegisterer
	ServiceInfos    []*ServiceInfo
	Services        map[string]interface{}
	GRPCConfig
	Metrics

	*sync.RWMutex
}

// GRPCConfig holds grpc init info
type GRPCConfig struct {
	Address        string
	MaxRecvMsgSize int
	MaxSendMsgSize int
}

// Metrics options
type Metrics struct {
	MetricsAddr    string
	GRPCHistogram  bool
	DisableMetrics bool
}

var (
	// ServiceCtxKey is the context.Context key to store the services context
	ServiceCtxKey = &contextKey{"ServiceContext"}
)

type contextKey struct {
	name string
}

func (k *contextKey) String() string {
	return "service context value " + k.name
}

// NewContext returns a new service InitContext
func NewContext(ctx context.Context, init *InitContext) (context.Context, error) {
	if init.KeysRepo == nil ||
		init.ContEnc == "" ||
		init.Logger == nil ||
		init.Address == "" ||
		init.G == nil ||
		init.CancelInterrupt == nil {
		return nil, errors.Wrap(errdef.ErrInternal, "invalid service init context values")
	}
	init.GrpcRegisterers = []GRPCRegisterer{}
	init.ServiceInfos = []*ServiceInfo{}
	init.Services = map[string]interface{}{}
	init.RWMutex = &sync.RWMutex{}
	return context.WithValue(ctx, ServiceCtxKey, init), nil
}

// FromContext returns service *InitContext from context
func FromContext(ctx context.Context) (*InitContext, error) {
	val := ctx.Value(ServiceCtxKey)
	if val == nil {
		return nil, errors.Wrap(errdef.ErrInternal, "services: found no Services context")
	}
	cval, ok := val.(*InitContext)
	if !ok {
		return nil, errors.Wrap(errdef.ErrInternal, "services: found Services context is not of type *InitContext")
	}
	return cval, nil
}
