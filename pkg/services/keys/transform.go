package keys

import (
	"time"

	pb "github.com/karantin2020/jwtis/api/keys/v1"
)

// NewAuthRequestFromPB transformer *pb.AuthRequest to *AuthRequest
func NewAuthRequestFromPB(msg *pb.AuthRequest) *AuthRequest {
	if msg == nil {
		return nil
	}
	var result = AuthRequest{
		KID: msg.KID,
	}
	return &result
}

// NewPBFromAuthRequest transformer *AuthRequest to *pb.AuthRequest
func NewPBFromAuthRequest(msg *AuthRequest) *pb.AuthRequest {
	if msg == nil {
		return nil
	}
	var result = pb.AuthRequest{
		KID: msg.KID,
	}
	return &result
}

// NewAuthResponseFromPB transformer *pb.AuthResponse to *AuthResponse
func NewAuthResponseFromPB(msg *pb.AuthResponse) *AuthResponse {
	if msg == nil {
		return nil
	}
	var result = AuthResponse{
		AuthJWT: msg.AuthJWT,
	}
	return &result
}

// NewPBFromAuthResponse transformer *AuthResponse to *pb.AuthResponse
func NewPBFromAuthResponse(msg *AuthResponse) *pb.AuthResponse {
	if msg == nil {
		return nil
	}
	var result = pb.AuthResponse{
		AuthJWT: msg.AuthJWT,
	}
	return &result
}

// NewRegisterRequestFromPB transformer *pb.RegisterRequest to *RegisterRequest
func NewRegisterRequestFromPB(msg *pb.RegisterRequest) *RegisterRequest {
	if msg == nil {
		return nil
	}
	var result = RegisterRequest{
		KID:             msg.KID,
		SigAlg:          msg.SigAlg,
		EncAlg:          msg.EncAlg,
		SigBits:         int(msg.SigBits),
		EncBits:         int(msg.EncBits),
		Expiry:          time.Duration(msg.Expiry),
		AuthTTL:         time.Duration(msg.AuthTTL),
		RefreshTTL:      time.Duration(msg.RefreshTTL),
		RefreshStrategy: msg.RefreshStrategy,
	}
	return &result
}

// NewPBFromRegisterRequest transformer *RegisterRequest to *pb.RegisterRequest
func NewPBFromRegisterRequest(msg *RegisterRequest) *pb.RegisterRequest {
	if msg == nil {
		return nil
	}
	var result = pb.RegisterRequest{
		KID:             msg.KID,
		SigAlg:          msg.SigAlg,
		EncAlg:          msg.EncAlg,
		SigBits:         int32(msg.SigBits),
		EncBits:         int32(msg.EncBits),
		Expiry:          int64(msg.Expiry),
		AuthTTL:         int64(msg.AuthTTL),
		RefreshTTL:      int64(msg.RefreshTTL),
		RefreshStrategy: msg.RefreshStrategy,
	}
	return &result
}

// NewRegisterResponseFromPB transformer *pb.RegisterResponse to *RegisterResponse
func NewRegisterResponseFromPB(msg *pb.RegisterResponse) *RegisterResponse {
	if msg == nil {
		return nil
	}
	var result = RegisterResponse{}
	return &result
}

// NewPBFromRegisterResponse transformer *RegisterResponse to *pb.RegisterResponse
func NewPBFromRegisterResponse(msg *RegisterResponse) *pb.RegisterResponse {
	if msg == nil {
		return nil
	}
	var result = pb.RegisterResponse{}
	return &result
}

// NewUpdateKeysRequestFromPB transformer *pb.UpdateKeysRequest to *UpdateKeysRequest
func NewUpdateKeysRequestFromPB(msg *pb.UpdateKeysRequest) *UpdateKeysRequest {
	if msg == nil {
		return nil
	}
	var result = UpdateKeysRequest{
		KID:             msg.KID,
		SigAlg:          msg.SigAlg,
		EncAlg:          msg.EncAlg,
		SigBits:         int(msg.SigBits),
		EncBits:         int(msg.EncBits),
		Expiry:          time.Duration(msg.Expiry),
		AuthTTL:         time.Duration(msg.AuthTTL),
		RefreshTTL:      time.Duration(msg.RefreshTTL),
		RefreshStrategy: msg.RefreshStrategy,
	}
	return &result
}

// NewPBFromUpdateKeysRequest transformer *UpdateKeysRequest to *pb.UpdateKeysRequest
func NewPBFromUpdateKeysRequest(msg *UpdateKeysRequest) *pb.UpdateKeysRequest {
	if msg == nil {
		return nil
	}
	var result = pb.UpdateKeysRequest{
		KID:             msg.KID,
		SigAlg:          msg.SigAlg,
		EncAlg:          msg.EncAlg,
		SigBits:         int32(msg.SigBits),
		EncBits:         int32(msg.EncBits),
		Expiry:          int64(msg.Expiry),
		AuthTTL:         int64(msg.AuthTTL),
		RefreshTTL:      int64(msg.RefreshTTL),
		RefreshStrategy: msg.RefreshStrategy,
	}
	return &result
}

// NewUpdateKeysResponseFromPB transformer *pb.UpdateKeysResponse to *UpdateKeysResponse
func NewUpdateKeysResponseFromPB(msg *pb.UpdateKeysResponse) *UpdateKeysResponse {
	if msg == nil {
		return nil
	}
	var result UpdateKeysResponse
	return &result
}

// NewPBFromUpdateKeysResponse transformer *UpdateKeysResponse to *pb.UpdateKeysResponse
func NewPBFromUpdateKeysResponse(msg *UpdateKeysResponse) *pb.UpdateKeysResponse {
	if msg == nil {
		return nil
	}
	var result pb.UpdateKeysResponse
	return &result
}

// NewListKeysRequestFromPB transformer *pb.ListKeysRequest to *ListKeysRequest
func NewListKeysRequestFromPB(msg *pb.ListKeysRequest) *ListKeysRequest {
	if msg == nil {
		return nil
	}
	var result ListKeysRequest
	result.Query = msg.Query
	return &result
}

// NewPBFromListKeysRequest transformer *ListKeysRequest to *pb.ListKeysRequest
func NewPBFromListKeysRequest(msg *ListKeysRequest) *pb.ListKeysRequest {
	if msg == nil {
		return nil
	}
	var result pb.ListKeysRequest
	result.Query = msg.Query
	return &result
}

// NewListKeysResponseFromPB transformer *pb.ListKeysResponse to *ListKeysResponse
func NewListKeysResponseFromPB(msg *pb.ListKeysResponse) *ListKeysResponse {
	if msg == nil {
		return nil
	}
	var result = ListKeysResponse{}
	return &result
}

// NewPBFromListKeysResponse transformer *ListKeysResponse to *pb.ListKeysResponse
func NewPBFromListKeysResponse(msg *ListKeysResponse) *pb.ListKeysResponse {
	if msg == nil {
		return nil
	}
	var result = pb.ListKeysResponse{}
	return &result
}

// NewDelKeysRequestFromPB transformer *pb.DelKeysRequest to *DelKeysRequest
func NewDelKeysRequestFromPB(msg *pb.DelKeysRequest) *DelKeysRequest {
	if msg == nil {
		return nil
	}
	var result DelKeysRequest
	result.KID = msg.KID
	return &result
}

// NewPBFromDelKeysRequest transformer *DelKeysRequest to *pb.DelKeysRequest
func NewPBFromDelKeysRequest(msg *DelKeysRequest) *pb.DelKeysRequest {
	if msg == nil {
		return nil
	}
	var result pb.DelKeysRequest
	result.KID = msg.KID
	return &result
}

// NewDelKeysResponseFromPB transformer *pb.DelKeysResponse to *DelKeysResponse
func NewDelKeysResponseFromPB(msg *pb.DelKeysResponse) *DelKeysResponse {
	if msg == nil {
		return nil
	}
	var result DelKeysResponse
	return &result
}

// NewPBFromDelKeysResponse transformer *DelKeysResponse to *pb.DelKeysResponse
func NewPBFromDelKeysResponse(msg *DelKeysResponse) *pb.DelKeysResponse {
	if msg == nil {
		return nil
	}
	var result pb.DelKeysResponse
	return &result
}

// NewPublicKeysRequestFromPB transformer *pb.PublicKeysRequest to *PublicKeysRequest
func NewPublicKeysRequestFromPB(msg *pb.PublicKeysRequest) *PublicKeysRequest {
	if msg == nil {
		return nil
	}
	var result PublicKeysRequest
	result.KID = msg.KID
	return &result
}

// NewPBFromPublicKeysRequest transformer *PublicKeysRequest to *pb.PublicKeysRequest
func NewPBFromPublicKeysRequest(msg *PublicKeysRequest) *pb.PublicKeysRequest {
	if msg == nil {
		return nil
	}
	var result pb.PublicKeysRequest
	result.KID = msg.KID
	return &result
}

// NewPublicKeysResponseFromPB transformer *pb.PublicKeysResponse to *PublicKeysResponse
func NewPublicKeysResponseFromPB(msg *pb.PublicKeysResponse) *PublicKeysResponse {
	if msg == nil {
		return nil
	}
	var result = PublicKeysResponse{}
	return &result
}

// NewPBFromPublicKeysResponse transformer *PublicKeysResponse to *pb.PublicKeysResponse
func NewPBFromPublicKeysResponse(msg *PublicKeysResponse) *pb.PublicKeysResponse {
	if msg == nil {
		return nil
	}
	var result = pb.PublicKeysResponse{}
	return &result
}
