package jwt

import (
	apiJWT "github.com/karantin2020/jwtis/api/jwt/v1"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

// NewNewJWTRequestFromPB transformer *apiJWT.NewJWTRequest to *NewJWTRequest
func NewNewJWTRequestFromPB(msg *apiJWT.NewJWTRequest) *NewJWTRequest {
	if msg == nil {
		return nil
	}
	// claims := msg.GetClaims()
	result := NewJWTRequest{
		KID: msg.GetKID(),
	}
	// err :=
	return &result
}

// NewPBFromNewJWTRequest transformer *NewJWTRequest to *apiJWT.NewJWTRequest
func NewPBFromNewJWTRequest(msg *NewJWTRequest) *apiJWT.NewJWTRequest {
	if msg == nil {
		return nil
	}
	var result apiJWT.NewJWTRequest
	return &result
}

// NewNewJWTResponseFromPB transformer *apiJWT.NewJWTResponse to *NewJWTResponse
func NewNewJWTResponseFromPB(msg *apiJWT.NewJWTResponse) *NewJWTResponse {
	if msg == nil {
		return nil
	}
	var result = NewJWTResponse{
		ID:           msg.ID,
		AccessToken:  msg.AccessToken,
		RefreshToken: msg.RefreshToken,
		Expiry:       jwt.NumericDate(msg.Expiry),
	}
	return &result
}

// NewPBFromNewJWTResponse transformer *NewJWTResponse to *apiJWT.NewJWTResponse
func NewPBFromNewJWTResponse(msg *NewJWTResponse) *apiJWT.NewJWTResponse {
	if msg == nil {
		return nil
	}
	var result = apiJWT.NewJWTResponse{
		ID:           msg.ID,
		AccessToken:  msg.AccessToken,
		RefreshToken: msg.RefreshToken,
		Expiry:       int64(msg.Expiry),
	}
	return &result
}

// NewRenewJWTRequestFromPB transformer *apiJWT.RenewJWTRequest to *RenewJWTRequest
func NewRenewJWTRequestFromPB(msg *apiJWT.RenewJWTRequest) *RenewJWTRequest {
	if msg == nil {
		return nil
	}
	var result = RenewJWTRequest{
		KID:             msg.KID,
		RefreshToken:    msg.RefreshToken,
		RefreshStrategy: msg.RefreshStrategy,
	}
	return &result
}

// NewPBFromRenewJWTRequest transformer *RenewJWTRequest to *apiJWT.RenewJWTRequest
func NewPBFromRenewJWTRequest(msg *RenewJWTRequest) *apiJWT.RenewJWTRequest {
	if msg == nil {
		return nil
	}
	var result = apiJWT.RenewJWTRequest{
		KID:             msg.KID,
		RefreshToken:    msg.RefreshToken,
		RefreshStrategy: msg.RefreshStrategy,
	}
	return &result
}

// NewRenewJWTResponseFromPB transformer *apiJWT.RenewJWTResponse to *RenewJWTResponse
func NewRenewJWTResponseFromPB(msg *apiJWT.RenewJWTResponse) *RenewJWTResponse {
	if msg == nil {
		return nil
	}
	var result = RenewJWTResponse{
		ID:           msg.ID,
		AccessToken:  msg.AccessToken,
		RefreshToken: msg.RefreshToken,
		Expiry:       jwt.NumericDate(msg.Expiry),
	}
	return &result
}

// NewPBFromRenewJWTResponse transformer *RenewJWTResponse to *apiJWT.RenewJWTResponse
func NewPBFromRenewJWTResponse(msg *RenewJWTResponse) *apiJWT.RenewJWTResponse {
	if msg == nil {
		return nil
	}
	var result = apiJWT.RenewJWTResponse{
		ID:           msg.ID,
		AccessToken:  msg.AccessToken,
		RefreshToken: msg.RefreshToken,
		Expiry:       int64(msg.Expiry),
	}
	return &result
}

// NewRevokeJWTRequestFromPB transformer *apiJWT.RevokeJWTRequest to *RevokeJWTRequest
func NewRevokeJWTRequestFromPB(msg *apiJWT.RevokeJWTRequest) *RevokeJWTRequest {
	if msg == nil {
		return nil
	}
	var result = RevokeJWTRequest{
		KID:          msg.KID,
		ID:           msg.ID,
		RefreshToken: msg.RefreshToken,
	}
	return &result
}

// NewPBFromRevokeJWTRequest transformer *RevokeJWTRequest to *apiJWT.RevokeJWTRequest
func NewPBFromRevokeJWTRequest(msg *RevokeJWTRequest) *apiJWT.RevokeJWTRequest {
	if msg == nil {
		return nil
	}
	var result = apiJWT.RevokeJWTRequest{
		KID:          msg.KID,
		ID:           msg.ID,
		RefreshToken: msg.RefreshToken,
	}
	return &result
}

// NewRevokeJWTResponseFromPB transformer *apiJWT.RevokeJWTResponse to *RevokeJWTResponse
func NewRevokeJWTResponseFromPB(msg *apiJWT.RevokeJWTResponse) *RevokeJWTResponse {
	if msg == nil {
		return nil
	}
	return &RevokeJWTResponse{}
}

// NewPBFromRevokeJWTResponse transformer *RevokeJWTResponse to *apiJWT.RevokeJWTResponse
func NewPBFromRevokeJWTResponse(msg *RevokeJWTResponse) *apiJWT.RevokeJWTResponse {
	if msg == nil {
		return nil
	}
	return &apiJWT.RevokeJWTResponse{}
}
