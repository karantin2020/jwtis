package keys

import (
	"time"

	"github.com/karantin2020/jwtis/pkg/repos/keys"
)

// // KeysOptions represents default sig ang enc options
// type KeysOptions struct {
// 	SigAlg          string        // Algorithm to be used for sign
// 	SigBits         int           // Key size in bits for sign
// 	EncAlg          string        // Algorithm to be used for encrypt
// 	EncBits         int           // Key size in bits for encrypt
// 	Expiry          time.Duration // Value for keys ttl
// 	AuthTTL         time.Duration // Value for auth jwt ttl
// 	RefreshTTL      time.Duration // Value for refresh jwt ttl
// 	RefreshStrategy string        // optional, values are: 'refreshBoth', 'refreshOnExpire', 'noRefresh' (default)
// }

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
