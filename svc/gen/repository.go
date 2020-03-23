package gen

import (
	"context"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

var (
// // ErrNotImplemented status error
// ErrNotImplemented = status.Error(codes.Unimplemented, "method not implemented")
)

/**
type MysqlConfig struct {
	Host              string `env:"DB_READ_HOST" envDefault:"local-gen"`
	Port              string `env:"DB_READ_PORT" envDefault:"3306"`
	ConnectionTimeout int    `env:"DB_READ_CONNECTION_TIMEOUT" envDefault:"5"`
	MaxConnLifetime   int    `env:"DB_READ_MAX_CONN_LIFETIME" envDefault:"0"`
	MaxIdleConns      int    `env:"DB_READ_MAX_IDLE_CONNS" envDefault:"2"`
	MaxOpenConns      int    `env:"DB_READ_MAX_OPEN_CONNS" envDefault:"0"`
	ReadTimeout       int    `env:"DB_READ_READ_TIMEOUT" envDefault:"360"`
	Username          string `env:"DB_READ_USERNAME" envDefault:"root"`
	Password          string `env:"DB_READ_PASSWORD" envDefault:"foobar"`
	DatabaseName      string `env:"DB_READ_DATABASE" envDefault:"gen"`
}
**/

/*
Repository interface
*/
type Repository interface {
	NewJWT(ctx context.Context, req *NewJWTRequest) (*NewJWTResponse, error)
	RenewJWT(ctx context.Context, req *RenewJWTRequest) (*RenewJWTResponse, error)
	RevokeJWT(ctx context.Context, req *RevokeJWTRequest) (*RevokeJWTResponse, error)
	Auth(ctx context.Context, req *AuthRequest) (*AuthResponse, error)
	Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error)
	UpdateKeys(ctx context.Context, req *UpdateKeysRequest) (*UpdateKeysResponse, error)
	ListKeys(ctx context.Context, req *ListKeysRequest) (*ListKeysResponse, error)
	DelKeys(ctx context.Context, req *DelKeysRequest) (*DelKeysResponse, error)
	PublicKeys(ctx context.Context, req *PublicKeysRequest) (*PublicKeysResponse, error)
	Ping(ctx context.Context, req *PingRequest) (*PingResponse, error)
	Ready(ctx context.Context, req *ReadyRequest) (*ReadyResponse, error)
}

type repositoryImpl struct {
	log log.Logger
	db  interface{} // TODO : use your own kind, e.g. *mongo.Client
}

// NewRepository constructor
func NewRepository(logger log.Logger, db interface{}) Repository {
	return &repositoryImpl{log: logger, db: db}
}

// NewJWT repository method
func (r *repositoryImpl) NewJWT(ctx context.Context, req *NewJWTRequest) (*NewJWTResponse, error) {
	level.Error(r.log).Log("repository", "repository not implemented")
	return nil, ErrUnimplemented
}

// RenewJWT repository method
func (r *repositoryImpl) RenewJWT(ctx context.Context, req *RenewJWTRequest) (*RenewJWTResponse, error) {
	level.Error(r.log).Log("repository", "repository not implemented")
	return nil, ErrUnimplemented
}

// RevokeJWT repository method
func (r *repositoryImpl) RevokeJWT(ctx context.Context, req *RevokeJWTRequest) (*RevokeJWTResponse, error) {
	level.Error(r.log).Log("repository", "repository not implemented")
	return nil, ErrUnimplemented
}

// Auth repository method
func (r *repositoryImpl) Auth(ctx context.Context, req *AuthRequest) (*AuthResponse, error) {
	level.Error(r.log).Log("repository", "repository not implemented")
	return nil, ErrUnimplemented
}

// Register repository method
func (r *repositoryImpl) Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	level.Error(r.log).Log("repository", "repository not implemented yet")
	return nil, ErrUnimplemented
}

// UpdateKeys repository method
func (r *repositoryImpl) UpdateKeys(ctx context.Context, req *UpdateKeysRequest) (*UpdateKeysResponse, error) {
	level.Error(r.log).Log("repository", "repository not implemented")
	return nil, ErrUnimplemented
}

// ListKeys repository method
func (r *repositoryImpl) ListKeys(ctx context.Context, req *ListKeysRequest) (*ListKeysResponse, error) {
	level.Error(r.log).Log("repository", "repository not implemented")
	return nil, ErrUnimplemented
}

// DelKeys repository method
func (r *repositoryImpl) DelKeys(ctx context.Context, req *DelKeysRequest) (*DelKeysResponse, error) {
	level.Error(r.log).Log("repository", "repository not implemented")
	return nil, ErrUnimplemented
}

// PublicKeys repository method
func (r *repositoryImpl) PublicKeys(ctx context.Context, req *PublicKeysRequest) (*PublicKeysResponse, error) {
	level.Error(r.log).Log("repository", "repository not implemented")
	return nil, ErrUnimplemented
}

// Ping repository method
func (r *repositoryImpl) Ping(ctx context.Context, req *PingRequest) (*PingResponse, error) {
	level.Error(r.log).Log("repository", "repository not implemented")
	return nil, ErrUnimplemented
}

// Ready repository method
func (r *repositoryImpl) Ready(ctx context.Context, req *ReadyRequest) (*ReadyResponse, error) {
	level.Error(r.log).Log("repository", "repository not implemented")
	return nil, ErrUnimplemented
}
