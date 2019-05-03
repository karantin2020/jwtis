package grpc_client

import (
	"context"
	"encoding/json"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	jwthttp "github.com/karantin2020/jwtis/http"
	pb "github.com/karantin2020/jwtis/http/pb"
	"gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

var _ = codes.OK
var _ = status.Code(nil)

// Client implements JWTIS grpc client
type Client struct {
	cfg    Config
	client pb.JWTISClient
}

// Config is a set of configs for Client
type Config struct {
	// ID is public id of the client used to identify it's key id on JWTIS
	ID string

	// PublicSigKey is public sign key
	PublicSigKey jose.JSONWebKey

	// PublicEncKey is public encryption key
	PublicEncKey jose.JSONWebKey

	// IssuerURL is the JWTIS endpoint
	IssuerURL string

	// Expires specifies how long client keys are valid for.
	Expires time.Duration
}

// New returns new instance of Client
func New(pbclient pb.JWTISClient) *Client {
	return &Client{client: pbclient}
}

// NewJWT func requests a new jwt token
func (c *Client) NewJWT(claims map[string]interface{}) (*jwthttp.TokenResponse, error) {
	jclaims, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	return toJWTTok(c.client.NewJWT(context.Background(),
		&pb.NewTokenRequest{Kid: c.cfg.ID, Claims: jclaims}))
}

// RenewJWT func requests renew tokens
func (c *Client) RenewJWT(refreshToken, refreshStrategy string) (*jwthttp.TokenResponse, error) {
	return toJWTTok(c.client.RenewJWT(context.Background(),
		&pb.RenewTokenRequest{
			Kid:             c.cfg.ID,
			RefreshToken:    refreshToken,
			RefreshStrategy: refreshStrategy,
		}))
}

func toJWTTok(tok *pb.TokenResponse, err error) (*jwthttp.TokenResponse, error) {
	if err != nil {
		return nil, err
	}
	return &jwthttp.TokenResponse{
		ID:           tok.ID,
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		Expiry:       jwt.NumericDate(tok.Expiry),
	}, nil
}
