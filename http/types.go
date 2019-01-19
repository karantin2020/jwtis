package http

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"

	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

// NewTokenRequest sent to jwtis to fetch new jwt
// ClientToken {string} - must be in header
type NewTokenRequest struct {
	Kid string `json:"kid"` // Keys id to use
	// AccessTokenValidTime  Duration               `json:"access_token_valid_time,omitempty"`
	// RefreshTokenValidTime Duration               `json:"refresh_token_valid_time,omitempty"`
	Claims map[string]interface{} `json:"claims,omitempty"` // Custom claims
}

// RenewTokenRequest sent to jwtis to fetch new jwt
// ClientToken {string} - must be in header
type RenewTokenRequest struct {
	Kid string `json:"kid"` // Keys id to use
	// AccessTokenValidTime  Duration `json:"access_token_valid_time,omitempty"`
	// RefreshTokenValidTime Duration `json:"refresh_token_valid_time,omitempty"`
	RefreshToken string `json:"refresh_token"`
}

// TokenResponse sent to client that requested tokens
type TokenResponse struct {
	ID           string          `json:"id"`
	AccessToken  string          `json:"access_token"`  // Short lived auth token
	RefreshToken string          `json:"refresh_token"` // Long lived refresh token
	Expiry       jwt.NumericDate `json:"expiry"`
}

// Token represents the credentials used to authenticate
// the requests
// This is a copy of https://github.com/golang/oauth2 Token
type Token struct {
	// AccessToken is the token that authenticates
	// the requests
	AccessToken string `json:"access_token"`

	// TokenType is the type of token.
	// The Type method returns either this or "Bearer".
	// By default this field is empty for jwtis purposes
	TokenType string `json:"token_type,omitempty"`

	// RefreshToken is a token that's used by the application
	// (as opposed to the user) to refresh the access token
	// if it expires.
	RefreshToken string `json:"refresh_token,omitempty"`

	// Expiry is the optional expiration time of the access token.
	//
	// If zero, TokenSource implementations will reuse the same
	// token forever and RefreshToken or equivalent
	// mechanisms for that TokenSource will not be used.
	Expiry time.Time `json:"expiry,omitempty"`

	// raw optionally contains extra metadata from the server
	// when updating a token.
	raw interface{}
}

// RegisterClientRequest sent to jwtis to register new client
type RegisterClientRequest struct {
	Expiry Duration `json:"expiry,omitempty"` // keys ttl, optional

	SigAlg  string `json:"sig_alg,omitempty"`  // default algorithn to be used for sign, optional
	SigBits int    `json:"sig_bits,omitempty"` // default key size in bits for sign, optional
	EncAlg  string `json:"enc_alg,omitempty"`  // default algorithn to be used for encrypt, optional
	EncBits int    `json:"enc_bits,omitempty"` // default key size in bits for encrypt, optional

	AuthTTL    Duration `json:"auth_ttl,omitempty"`    // default auth jwt ttl, optional
	RefreshTTL Duration `json:"refresh_ttl,omitempty"` // default refresh jwt ttl, optional
}

// RegisterClientResponse sent to client after it's registration
type RegisterClientResponse struct {
	Kid         string          `json:"kid,omitempty"`          // Keys id to use
	ClientToken string          `json:"client_token,omitempty"` // Client token given after registration [reserved]
	PubSigKey   jose.JSONWebKey `json:"pub_sig_key,omitempty"`  // Public sign key to verify AccessTokens
	PubEncKey   jose.JSONWebKey `json:"pub_enc_key,omitempty"`  // Public enc key to decrypt RefreshTokens
	Expiry      jwt.NumericDate `json:"expiry,omitempty"`
	Valid       bool            `json:"valid,omitempty"`
}

// PubKeysClientRequest fetch public keys
type PubKeysClientRequest struct {
	Kid string `json:"kid"` // Keys id to use
}

// PubKeysResponse holds public keys
type PubKeysResponse struct {
	Kid       string          `json:"kid"`         // Keys id to use
	PubSigKey jose.JSONWebKey `json:"pub_sig_key"` // Public sign key to verify AccessTokens
	PubEncKey jose.JSONWebKey `json:"pub_enc_key"` // Public enc key to decrypt RefreshTokens
}

// ===== Error responses ====== //

// ErrorRequest describes response if service responses with error
type ErrorRequest struct {
	Status int         `json:"status"`
	Errors []ErrorBody `json:"errors"`
}

// ErrorBody hold error information
type ErrorBody struct {
	Source string `json:"source"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// ===== Marshallers ===== //

// Duration type
type Duration int64

// MarshalJSON func
func (d Duration) MarshalJSON() ([]byte, error) {
	return strconv.AppendInt([]byte{}, int64(d), 10), nil
}

// UnmarshalJSON func
func (d *Duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case int64:
		*d = Duration(value)
		return nil
	case float64:
		*d = Duration(value)
		return nil
	case string:
		rv, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		// fmt.Printf("%+v\n", rv)
		*d = Duration(int64(rv))
		return nil
	default:
		return errors.New("invalid duration")
	}
}
