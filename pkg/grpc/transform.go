package grpc

import (
	"time"

	endpoint "github.com/karantin2020/jwtis/pkg/endpoint"
	pb "github.com/karantin2020/jwtis/pkg/grpc/pb"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

// NewNewJWTRequestFromPB transformer *pb.NewJWTRequest to *endpoint.NewJWTRequest
func NewNewJWTRequestFromPB(msg *pb.NewJWTRequest) *endpoint.NewJWTRequest {
	if msg == nil {
		return nil
	}
	var result endpoint.NewJWTRequest
	result.KID = msg.KID
	result.Claims = msg.Claims
	return &result
}

// NewPBFromNewJWTRequest transformer *endpoint.NewJWTRequest to *pb.NewJWTRequest
func NewPBFromNewJWTRequest(msg *endpoint.NewJWTRequest) *pb.NewJWTRequest {
	if msg == nil {
		return nil
	}
	var result pb.NewJWTRequest
	result.KID = msg.KID
	result.Claims = msg.Claims
	return &result
}

// NewNewJWTReplyFromPB transformer *pb.NewJWTReply to *endpoint.NewJWTResponse
func NewNewJWTReplyFromPB(msg *pb.NewJWTReply) *endpoint.NewJWTResponse {
	if msg == nil {
		return nil
	}
	var result endpoint.NewJWTResponse
	result.Pair.ID = msg.ID
	result.Pair.AccessToken = msg.AccessToken
	result.Pair.RefreshToken = msg.RefreshToken
	result.Pair.Expiry = jwt.NumericDate(msg.Expiry)
	return &result
}

// NewPBFromNewJWTReply transformer *endpoint.NewJWTResponse to *pb.NewJWTReply
func NewPBFromNewJWTReply(msg *endpoint.NewJWTResponse) *pb.NewJWTReply {
	if msg == nil {
		return nil
	}
	var result pb.NewJWTReply
	result.ID = msg.Pair.ID
	result.AccessToken = msg.Pair.AccessToken
	result.RefreshToken = msg.Pair.RefreshToken
	result.Expiry = int64(msg.Pair.Expiry)
	return &result
}

// NewRenewJWTRequestFromPB transformer *pb.RenewJWTRequest to *endpoint.RenewJWTRequest
func NewRenewJWTRequestFromPB(msg *pb.RenewJWTRequest) *endpoint.RenewJWTRequest {
	if msg == nil {
		return nil
	}
	var result endpoint.RenewJWTRequest
	result.KID = msg.KID
	result.RefreshToken = msg.RefreshToken
	result.RefreshStrategy = msg.RefreshStrategy
	return &result
}

// NewPBFromRenewJWTRequest transformer *endpoint.RenewJWTRequest to *pb.RenewJWTRequest
func NewPBFromRenewJWTRequest(msg *endpoint.RenewJWTRequest) *pb.RenewJWTRequest {
	if msg == nil {
		return nil
	}
	var result pb.RenewJWTRequest
	result.KID = msg.KID
	result.RefreshToken = msg.RefreshToken
	result.RefreshStrategy = msg.RefreshStrategy
	return &result
}

// NewRenewJWTReplyFromPB transformer *pb.RenewJWTReply to *endpoint.RenewJWTResponse
func NewRenewJWTReplyFromPB(msg *pb.RenewJWTReply) *endpoint.RenewJWTResponse {
	if msg == nil {
		return nil
	}
	var result endpoint.RenewJWTResponse
	return &result
}

// NewPBFromRenewJWTReply transformer *endpoint.RenewJWTResponse to *pb.RenewJWTReply
func NewPBFromRenewJWTReply(msg *endpoint.RenewJWTResponse) *pb.RenewJWTReply {
	if msg == nil {
		return nil
	}
	var result pb.RenewJWTReply
	return &result
}

// NewRevokeJWTRequestFromPB transformer *pb.RevokeJWTRequest to *RevokeJWTRequest
func NewRevokeJWTRequestFromPB(msg *pb.RevokeJWTRequest) *endpoint.RevokeJWTRequest {
	if msg == nil {
		return nil
	}
	var result endpoint.RevokeJWTRequest
	result.KID = msg.KID
	result.ID = msg.ID
	result.RefreshToken = msg.RefreshToken
	return &result
}

// NewPBFromRevokeJWTRequest transformer *RevokeJWTRequest to *pb.RevokeJWTRequest
func NewPBFromRevokeJWTRequest(msg *endpoint.RevokeJWTRequest) *pb.RevokeJWTRequest {
	if msg == nil {
		return nil
	}
	var result pb.RevokeJWTRequest
	result.KID = msg.KID
	result.ID = msg.ID
	result.RefreshToken = msg.RefreshToken
	return &result
}

// NewRevokeJWTReplyFromPB transformer *pb.RevokeJWTReply to *endpoint.RevokeJWTResponse
func NewRevokeJWTReplyFromPB(msg *pb.RevokeJWTReply) *endpoint.RevokeJWTResponse {
	if msg == nil {
		return nil
	}
	var result endpoint.RevokeJWTResponse
	return &result
}

// NewPBFromRevokeJWTReply transformer *RevokeJWTReply to *pb.RevokeJWTReply
func NewPBFromRevokeJWTReply(msg *endpoint.RevokeJWTResponse) *pb.RevokeJWTReply {
	if msg == nil {
		return nil
	}
	var result pb.RevokeJWTReply
	return &result
}

// NewAuthRequestFromPB transformer *pb.AuthRequest to *AuthRequest
func NewAuthRequestFromPB(msg *pb.AuthRequest) *endpoint.AuthRequest {
	if msg == nil {
		return nil
	}
	var result AuthRequest
	result.KID = msg.KID
	return &result
}

// NewPBFromAuthRequest transformer *AuthRequest to *pb.AuthRequest
func NewPBFromAuthRequest(msg *endpoint.AuthRequest) *pb.AuthRequest {
	if msg == nil {
		return nil
	}
	var result pb.AuthRequest
	result.KID = msg.KID
	return &result
}

// NewAuthReplyFromPB transformer *pb.AuthReply to *AuthReply
func NewAuthReplyFromPB(msg *pb.AuthReply) *endpoint.AuthResponse {
	if msg == nil {
		return nil
	}
	var result endpoint.AuthResponse
	result.Token = msg.AuthJWT
	return &result
}

// NewPBFromAuthReply transformer *AuthReply to *pb.AuthReply
func NewPBFromAuthReply(msg *endpoint.AuthResponse) *pb.AuthReply {
	if msg == nil {
		return nil
	}
	var result pb.AuthReply
	result.AuthJWT = msg.Token
	return &result
}

// NewRegisterRequestFromPB transformer *pb.RegisterRequest to *RegisterRequest
func NewRegisterRequestFromPB(msg *pb.RegisterRequest) *endpoint.RegisterRequest {
	if msg == nil {
		return nil
	}
	var result endpoint.RegisterRequest
	result.KID = msg.KID
	result.Opts.Expiry = time.Duration(msg.Expiry)
	result.Opts.SigAlg = msg.SigAlg
	result.Opts.SigBits = int(msg.SigBits)
	result.Opts.EncAlg = msg.EncAlg
	result.Opts.EncBits = int(msg.EncBits)
	result.Opts.AuthTTL = time.Duration(msg.AuthTTL)
	result.Opts.RefreshTTL = time.Duration(msg.RefreshTTL)
	result.Opts.RefreshStrategy = msg.RefreshStrategy
	return &result
}

// NewPBFromRegisterRequest transformer *RegisterRequest to *pb.RegisterRequest
func NewPBFromRegisterRequest(msg *endpoint.RegisterRequest) *pb.RegisterRequest {
	if msg == nil {
		return nil
	}
	var result pb.RegisterRequest
	result.KID = msg.KID
	result.Expiry = int64(msg.Opts.Expiry)
	result.SigAlg = msg.Opts.SigAlg
	result.SigBits = int32(msg.Opts.SigBits)
	result.EncAlg = msg.Opts.EncAlg
	result.EncBits = int32(msg.Opts.EncBits)
	result.AuthTTL = int64(msg.Opts.AuthTTL)
	result.RefreshTTL = int64(msg.Opts.RefreshTTL)
	result.RefreshStrategy = msg.Opts.RefreshStrategy
	return &result
}

// NewRegisterReplyFromPB transformer *pb.RegisterReply to *endpoint.RegisterResponse
func NewRegisterReplyFromPB(msg *pb.RegisterReply) *endpoint.RegisterResponse {
	if msg == nil {
		return nil
	}
	var result endpoint.RegisterResponse
	result.KID = msg.KID
	result.Keys.AuthJWT = msg.AuthJWT
	result.Keys.PubSigKey = msg.PubSigKey
	result.Keys.PubEncKey = msg.PubEncKey
	result.Keys.Expiry = msg.Expiry
	result.Keys.Valid = msg.Valid
	result.Keys.RefreshStrategy = msg.RefreshStrategy
	return &result
}

// NewPBFromRegisterReply transformer *RegisterReply to *pb.RegisterReply
func NewPBFromRegisterReply(msg *endpoint.RegisterResponse) *pb.RegisterReply {
	if msg == nil {
		return nil
	}
	var result pb.RegisterReply
	result.KID = msg.KID
	result.AuthJWT = msg.AuthJWT
	result.PubSigKey = msg.PubSigKey
	result.PubEncKey = msg.PubEncKey
	result.Expiry = msg.Expiry
	result.Valid = msg.Valid
	result.RefreshStrategy = msg.RefreshStrategy
	return &result
}

// NewUpdateKeysRequestFromPB transformer *pb.UpdateKeysRequest to *UpdateKeysRequest
func NewUpdateKeysRequestFromPB(msg *pb.UpdateKeysRequest) *endpoint.UpdateKeysRequest {
	if msg == nil {
		return nil
	}
	var result UpdateKeysRequest
	return &result
}

// NewPBFromUpdateKeysRequest transformer *UpdateKeysRequest to *pb.UpdateKeysRequest
func NewPBFromUpdateKeysRequest(msg *endpoint.UpdateKeysRequest) *pb.UpdateKeysRequest {
	if msg == nil {
		return nil
	}
	var result pb.UpdateKeysRequest
	return &result
}

// NewUpdateKeysReplyFromPB transformer *pb.UpdateKeysReply to *UpdateKeysReply
func NewUpdateKeysReplyFromPB(msg *pb.UpdateKeysReply) *endpoint.UpdateKeysReply {
	if msg == nil {
		return nil
	}
	var result UpdateKeysReply
	return &result
}

// NewPBFromUpdateKeysReply transformer *UpdateKeysReply to *pb.UpdateKeysReply
func NewPBFromUpdateKeysReply(msg *endpoint.UpdateKeysResponse) *pb.UpdateKeysReply {
	if msg == nil {
		return nil
	}
	var result pb.UpdateKeysReply
	return &result
}

// NewListKeysRequestFromPB transformer *pb.ListKeysRequest to *ListKeysRequest
func NewListKeysRequestFromPB(msg *pb.ListKeysRequest) *endpoint.ListKeysRequest {
	if msg == nil {
		return nil
	}
	var result ListKeysRequest
	result.Query = msg.Query
	return &result
}

// NewPBFromListKeysRequest transformer *ListKeysRequest to *pb.ListKeysRequest
func NewPBFromListKeysRequest(msg *endpoint.ListKeysRequest) *pb.ListKeysRequest {
	if msg == nil {
		return nil
	}
	var result pb.ListKeysRequest
	result.Query = msg.Query
	return &result
}

// NewKeysInfoFromPB transformer *pb.KeysInfo to *KeysInfo
func NewKeysInfoFromPB(msg *pb.KeysInfo) *endpoint.KeysInfo {
	if msg == nil {
		return nil
	}
	var result KeysInfo
	result.KID = msg.KID
	result.Expiry = msg.Expiry
	result.AuthTTL = msg.AuthTTL
	result.RefreshTTL = msg.RefreshTTL
	result.RefreshStrategy = msg.RefreshStrategy
	result.PubSigKey = msg.PubSigKey
	result.PubEncKey = msg.PubEncKey
	result.Locked = msg.Locked
	result.Valid = msg.Valid
	result.Expired = msg.Expired
	return &result
}

// NewPBFromKeysInfo transformer *KeysInfo to *pb.KeysInfo
func NewPBFromKeysInfo(msg *KeysInfo) *pb.KeysInfo {
	if msg == nil {
		return nil
	}
	var result pb.KeysInfo
	result.KID = msg.KID
	result.Expiry = msg.Expiry
	result.AuthTTL = msg.AuthTTL
	result.RefreshTTL = msg.RefreshTTL
	result.RefreshStrategy = msg.RefreshStrategy
	result.PubSigKey = msg.PubSigKey
	result.PubEncKey = msg.PubEncKey
	result.Locked = msg.Locked
	result.Valid = msg.Valid
	result.Expired = msg.Expired
	return &result
}

// NewListKeysReplyFromPB transformer *pb.ListKeysReply to *ListKeysReply
func NewListKeysReplyFromPB(msg *pb.ListKeysReply) *endpoint.ListKeysReply {
	if msg == nil {
		return nil
	}
	var result ListKeysReply
	for _, keys := range msg.Keys {
		elem := NewKeysInfoFromPB(keys)
		if elem != nil {
			result.Keys = append(result.Keys, *elem)
		}
	}
	return &result
}

// NewPBFromListKeysReply transformer *ListKeysReply to *pb.ListKeysReply
func NewPBFromListKeysReply(msg *endpoint.ListKeysResponse) *pb.ListKeysReply {
	if msg == nil {
		return nil
	}
	var result pb.ListKeysReply
	for _, keys := range msg.Keys {
		elem := NewPBFromKeysInfo(&keys)
		if elem != nil {
			result.Keys = append(result.Keys, elem)
		}
	}
	return &result
}

// NewDelKeysRequestFromPB transformer *pb.DelKeysRequest to *DelKeysRequest
func NewDelKeysRequestFromPB(msg *pb.DelKeysRequest) *endpoint.DelKeysRequest {
	if msg == nil {
		return nil
	}
	var result DelKeysRequest
	result.KID = msg.KID
	return &result
}

// NewPBFromDelKeysRequest transformer *DelKeysRequest to *pb.DelKeysRequest
func NewPBFromDelKeysRequest(msg *endpoint.DelKeysRequest) *pb.DelKeysRequest {
	if msg == nil {
		return nil
	}
	var result pb.DelKeysRequest
	result.KID = msg.KID
	return &result
}

// NewDelKeysReplyFromPB transformer *pb.DelKeysReply to *DelKeysReply
func NewDelKeysReplyFromPB(msg *pb.DelKeysReply) *endpoint.DelKeysReply {
	if msg == nil {
		return nil
	}
	var result DelKeysReply
	return &result
}

// NewPBFromDelKeysReply transformer *DelKeysReply to *pb.DelKeysReply
func NewPBFromDelKeysReply(msg *endpoint.DelKeysResponse) *pb.DelKeysReply {
	if msg == nil {
		return nil
	}
	var result pb.DelKeysReply
	return &result
}

// NewPublicKeysRequestFromPB transformer *pb.PublicKeysRequest to *PublicKeysRequest
func NewPublicKeysRequestFromPB(msg *pb.PublicKeysRequest) *endpoint.PublicKeysRequest {
	if msg == nil {
		return nil
	}
	var result PublicKeysRequest
	result.KID = msg.KID
	return &result
}

// NewPBFromPublicKeysRequest transformer *PublicKeysRequest to *pb.PublicKeysRequest
func NewPBFromPublicKeysRequest(msg *endpoint.PublicKeysRequest) *pb.PublicKeysRequest {
	if msg == nil {
		return nil
	}
	var result pb.PublicKeysRequest
	result.KID = msg.KID
	return &result
}

// NewPublicKeysReplyFromPB transformer *pb.PublicKeysReply to *PublicKeysReply
func NewPublicKeysReplyFromPB(msg *pb.PublicKeysReply) *endpoint.PublicKeysReply {
	if msg == nil {
		return nil
	}
	var result PublicKeysReply
	result.KID = msg.KID
	result.PubSigKey = msg.PubSigKey
	result.PubEncKey = msg.PubEncKey
	result.Expiry = msg.Expiry
	result.Valid = msg.Valid
	return &result
}

// NewPBFromPublicKeysReply transformer *PublicKeysReply to *pb.PublicKeysReply
func NewPBFromPublicKeysReply(msg *endpoint.PublicKeysResponse) *pb.PublicKeysReply {
	if msg == nil {
		return nil
	}
	var result pb.PublicKeysReply
	result.KID = msg.KID
	result.PubSigKey = msg.PubSigKey
	result.PubEncKey = msg.PubEncKey
	result.Expiry = msg.Expiry
	result.Valid = msg.Valid
	return &result
}
