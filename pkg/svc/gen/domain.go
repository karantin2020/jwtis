package gen

import (
	"time"

	"github.com/karantin2020/jwtis/pkg/repos/keys"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

// JWTPair holds auth and refresh tokens
type JWTPair struct {
	ID           string          `json:"id"`
	AccessToken  string          `json:"access_token"`            // Short lived auth token
	RefreshToken string          `json:"refresh_token,omitempty"` // Long lived refresh token
	Expiry       jwt.NumericDate `json:"expiry,omitempty"`
}

// KeysOptions represents default sig ang enc options
type KeysOptions struct {
	SigAlg          string        // Algorithm to be used for sign
	SigBits         int           // Key size in bits for sign
	EncAlg          string        // Algorithm to be used for encrypt
	EncBits         int           // Key size in bits for encrypt
	Expiry          time.Duration // Value for keys ttl
	AuthTTL         time.Duration // Value for auth jwt ttl
	RefreshTTL      time.Duration // Value for refresh jwt ttl
	RefreshStrategy string        // optional, values are: 'refreshBoth', 'refreshOnExpire', 'noRefresh' (default)
}

// NewJWTRequest message type
type NewJWTRequest struct {
	KID    string                 `json:"kid"`
	Claims map[string]interface{} `json:"claims"`
}

// NewJWTResponse message type
type NewJWTResponse struct {
	ID           string
	AccessToken  string
	RefreshToken string
	Expiry       jwt.NumericDate
}

// RenewJWTRequest message type
type RenewJWTRequest struct {
	KID             string
	RefreshToken    string
	RefreshStrategy string
}

// RenewJWTResponse message type
type RenewJWTResponse struct {
	ID           string
	AccessToken  string
	RefreshToken string
	Expiry       jwt.NumericDate
}

// RevokeJWTRequest message type
type RevokeJWTRequest struct {
	KID          string
	ID           string
	RefreshToken string
}

// RevokeJWTResponse message type
type RevokeJWTResponse struct {
}

// AuthRequest message type
type AuthRequest struct {
	KID string
}

// AuthResponse message type
type AuthResponse struct {
	AuthJWT string
}

// RegisterRequest message type
type RegisterRequest struct {
	KID             string
	SigAlg          string
	EncAlg          string
	SigBits         int
	EncBits         int
	Expiry          time.Duration
	AuthTTL         time.Duration
	RefreshTTL      time.Duration
	RefreshStrategy string
}

// RegisterResponse message type
type RegisterResponse struct {
	KID     string `json:"kid"`
	AuthJWT string
	Keys    *keys.SigEncKeys `json:"keys"`
}

// UpdateKeysRequest message type
type UpdateKeysRequest struct {
	KID             string
	SigAlg          string
	EncAlg          string
	SigBits         int
	EncBits         int
	Expiry          time.Duration
	AuthTTL         time.Duration
	RefreshTTL      time.Duration
	RefreshStrategy string
}

// UpdateKeysResponse message type
type UpdateKeysResponse struct {
	KID     string `json:"kid"`
	AuthJWT string
	Keys    *keys.SigEncKeys `json:"keys"`
}

// ListKeysRequest message type
type ListKeysRequest struct {
	Query string
}

// ListKeysResponse message type
type ListKeysResponse struct {
	KID  string
	Keys keys.InfoSet `json:"keys_list"`
}

// DelKeysRequest message type
type DelKeysRequest struct {
	KID string
}

// DelKeysResponse message type
type DelKeysResponse struct {
}

// PublicKeysRequest message type
type PublicKeysRequest struct {
	KID string
}

// PublicKeysResponse message type
type PublicKeysResponse struct {
	KID  string
	Keys *keys.SigEncKeys `json:"keys"`
}

// PingRequest message type
type PingRequest struct {
}

// PingResponse message type
type PingResponse struct {
	Status string
}

// ReadyRequest message type
type ReadyRequest struct {
}

// ReadyResponse message type
type ReadyResponse struct {
	Status string
	Start  jwt.NumericDate
	Up     time.Duration
}
