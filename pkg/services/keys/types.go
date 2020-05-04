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
	KID string `json:"kid"`
}

// AuthResponse message type
type AuthResponse struct {
	AuthJWT string `json:"authJWT"`
}

// RegisterRequest message type
type RegisterRequest struct {
	KID             string        `json:"kid"`
	SigAlg          string        `json:"sigAlg"`
	EncAlg          string        `json:"encAlg"`
	SigBits         int           `json:"sigBits"`
	EncBits         int           `json:"encBits"`
	Expiry          time.Duration `json:"expiry"`
	AuthTTL         time.Duration `json:"authTTL"`
	RefreshTTL      time.Duration `json:"refreshTTL"`
	RefreshStrategy string        `json:"refreshStrategy"`
}

// RegisterResponse message type
type RegisterResponse struct {
	KID     string           `json:"kid"`
	AuthJWT string           `json:"authJWT"`
	Keys    *keys.SigEncKeys `json:"keys"`
}

// UpdateKeysRequest message type
type UpdateKeysRequest struct {
	KID             string        `json:"kid"`
	SigAlg          string        `json:"sigAlg"`
	EncAlg          string        `json:"encAlg"`
	SigBits         int           `json:"sigBits"`
	EncBits         int           `json:"encBits"`
	Expiry          time.Duration `json:"expiry"`
	AuthTTL         time.Duration `json:"authTTL"`
	RefreshTTL      time.Duration `json:"refreshTTL"`
	RefreshStrategy string        `json:"refreshStrategy"`
}

// UpdateKeysResponse message type
type UpdateKeysResponse struct {
	KID     string           `json:"kid"`
	AuthJWT string           `json:"authJWT"`
	Keys    *keys.SigEncKeys `json:"keys"`
}

// ListKeysRequest message type
type ListKeysRequest struct {
	Query string `json:"query"`
}

// ListKeysResponse message type
type ListKeysResponse struct {
	KID  string       `json:"kid"`
	Keys keys.InfoSet `json:"keys_list"`
}

// DelKeysRequest message type
type DelKeysRequest struct {
	KID string `json:"kid"`
}

// DelKeysResponse message type
type DelKeysResponse struct {
}

// PublicKeysRequest message type
type PublicKeysRequest struct {
	KID string `json:"kid"`
}

// PublicKeysResponse message type
type PublicKeysResponse struct {
	KID  string           `json:"kid"`
	Keys *keys.SigEncKeys `json:"keys"`
}
