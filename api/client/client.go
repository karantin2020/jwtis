package client

import (
	"context"
	"time"

	// "google.golang.org/grpc/codes"
	// "google.golang.org/grpc/status"

	// jwthttp "github.com/karantin2020/jwtis/http"
	pb "github.com/karantin2020/jwtis/api/pb"
	"google.golang.org/grpc"
	"gopkg.in/square/go-jose.v2"
)

// var _ = codes.OK
// var _ = status.Code(nil)

// Client implements JWTIS grpc client
type Client struct {
	cfg          Config
	grpcOpts     []grpc.CallOption
	client       pb.JWTISClient
	PublicSigKey jose.JSONWebKey
	PublicEncKey jose.JSONWebKey
}

// ClientOpts represents struct with default client opts
type ClientOpts struct {
	Expiry          time.Duration
	SigAlg          string
	SigBits         int32
	EncAlg          string
	EncBits         int32
	AuthTTL         time.Duration
	RefreshTTL      time.Duration
	RefreshStrategy string
}

// Config is a set of configs for Client
type Config struct {
	// ID is public id of the client used to identify it's key id on JWTIS
	ID string

	ClientOpts
}

// New returns new instance of Client
func New(id string, clOpts ClientOpts,
	conn *grpc.ClientConn, opts ...grpc.CallOption) *Client {
	client := &Client{
		client:   pb.NewJWTISClient(conn),
		grpcOpts: opts,
		cfg: Config{
			ID: id,
		},
	}
	client.cfg.ClientOpts = clOpts
	return client
}

// Register registers new client  on JWTIS server if it wasn't registered yet
func (c *Client) Register() (*pb.RegisterClientResponse, error) {
	return c.client.Register(context.Background(), &pb.RegisterClientRequest{
		Kid:             c.cfg.ID,
		Expiry:          int64(c.cfg.Expiry),
		SigAlg:          c.cfg.SigAlg,
		SigBits:         c.cfg.SigBits,
		EncAlg:          c.cfg.EncAlg,
		EncBits:         c.cfg.EncBits,
		AuthTTL:         int64(c.cfg.AuthTTL),
		RefreshTTL:      int64(c.cfg.RefreshTTL),
		RefreshStrategy: c.cfg.RefreshStrategy,
	}, c.grpcOpts...)
}

// PublicKeys returns client public keys
func (c *Client) PublicKeys() (*pb.PubKeysResponse, error) {
	return c.client.PublicKeys(context.Background(), &pb.PubKeysRequest{
		Kid: c.cfg.ID,
	}, c.grpcOpts...)
}

// NewJWT(ctx context.Context, in *pb.NewTokenRequest, opts ...grpc.CallOption) (*pb.TokenResponse, error)
// // RenewJWT is called to refresh jwt token according
// // to refresh strategy
// RenewJWT(ctx context.Context, in *pb.RenewTokenRequest, opts ...grpc.CallOption) (*pb.TokenResponse, error)
// Register(ctx context.Context, in *pb.RegisterClientRequest, opts ...grpc.CallOption) (*pb.RegisterClientResponse, error)
// UpdateKeys(ctx context.Context, in *pb.RegisterClientRequest, opts ...grpc.CallOption) (*pb.RegisterClientResponse, error)
// DelKeys(ctx context.Context, in *pb.DelKeysRequest, opts ...grpc.CallOption) (*pb.DelKeysResponse, error)
// PublicKeys(ctx context.Context, in *pb.PubKeysRequest, opts ...grpc.CallOption) (*pb.PubKeysResponse, error)

// // NewJWT func requests a new jwt token
// func (c *Client) NewJWT(claims map[string]interface{}) (*jwthttp.TokenResponse, error) {
// 	jclaims, err := json.Marshal(claims)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return toJWTTok(c.client.NewJWT(context.Background(),
// 		&pb.NewTokenRequest{Kid: c.cfg.ID, Claims: jclaims}))
// }

// // RenewJWT func requests renew tokens
// func (c *Client) RenewJWT(refreshToken, refreshStrategy string) (*jwthttp.TokenResponse, error) {
// 	return toJWTTok(c.client.RenewJWT(context.Background(),
// 		&pb.RenewTokenRequest{
// 			Kid:             c.cfg.ID,
// 			RefreshToken:    refreshToken,
// 			RefreshStrategy: refreshStrategy,
// 		}))
// }

// func toJWTTok(tok *pb.TokenResponse, err error) (*jwthttp.TokenResponse, error) {
// 	if err != nil {
// 		return nil, err
// 	}
// 	return &jwthttp.TokenResponse{
// 		ID:           tok.ID,
// 		AccessToken:  tok.AccessToken,
// 		RefreshToken: tok.RefreshToken,
// 		Expiry:       jwt.NumericDate(tok.Expiry),
// 	}, nil
// }
