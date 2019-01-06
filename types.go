package jwtis

import (
	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

// NewTokenRequest sent to jwtis to fetch new jwt
type NewTokenRequest struct {
	Kid                   string          `json:"kid"`          // Keys id to use
	ClientToken           string          `json:"client_token"` // Client token given after registration
	AuthTokenValidTime    jwt.NumericDate `json:"auth_token_valid_time"`
	ResreshTokenValidTime jwt.NumericDate `json:"resresh_token_valid_time"`
	Claims                interface{}     `json:"claims"` // Custom claims
}

// RenewTokenRequest sent to jwtis to fetch new jwt
type RenewTokenRequest struct {
	Kid          string `json:"kid"`          // Keys id to use
	ClientToken  string `json:"client_token"` // Client token given after registration
	RefreshToken string `json:"refresh_token"`
}

// NewTokenResponse sent to client that requested tokens
type NewTokenResponse struct {
	AuthToken    string `json:"auth_token"`    // Short lived auth token
	RefreshToken string `json:"refresh_token"` // Long lived refresh token
}

// RegisterClientRequest sent to jwtis to register new client
type RegisterClientRequest struct {
	Kid string `json:"kid"` // Keys id to use

	// Sign and encrypt keys config. If not provided then use default JWTIS values
	SigAlg  string `json:"sig_alg"`  // algorithn to be used for sign
	SigBits string `json:"sig_bits"` // key size in bits for sign
	EncAlg  string `json:"enc_alg"`  // algorithn to be used for encrypt
	EncBits string `json:"enc_bits"` // key size in bits for encrypt
}

// RegisterClientResponse sent to client after it's registration
type RegisterClientResponse struct {
	Kid         string          `json:"kid"`          // Keys id to use
	ClientToken string          `json:"client_token"` // Client token given after registration
	PubSigKey   jose.JSONWebKey `json:"pub_sig_key"`  // Public sign key to verify AuthTokens
	PubEncKey   jose.JSONWebKey `json:"pub_enc_key"`  // Public enc key to decrypt RefreshTokens
}
