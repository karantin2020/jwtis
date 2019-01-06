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
}

// RegisterClientResponse sent to client after it's registration
type RegisterClientResponse struct {
	Kid         string          `json:"kid"`          // Keys id to use
	ClientToken string          `json:"client_token"` // Client token given after registration
	PubSigKey   jose.JSONWebKey `json:"pub_sig_key"`  // Public sign key to verify AuthTokens
}
