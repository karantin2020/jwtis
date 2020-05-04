package jwt

import (
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

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
