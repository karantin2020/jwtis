package gen_test

// import (
// 	"testing"

// 	. "github.com/karantin2020/jwtis/pkg/svc/gen"
// 	pb "github.com/karantin2020/jwtis/pkg/svc/pb"
// 	"github.com/stretchr/testify/assert"
// )

// // test transformer *pb.NewJWTRequest to *NewJWTRequest
// func TestNewJWTRequestFromPB(t *testing.T) {
// 	// TODO : fill me up
// 	payload := pb.NewJWTRequest{

// 		KID:    "",
// 		Claims: []byte{},
// 	}
// 	result := NewNewJWTRequestFromPB(&payload)
// 	assert.Equal(t, payload.KID, result.KID)
// 	assert.Equal(t, payload.Claims, result.Claims)

// }

// // test transformer *NewJWTRequest to *pb.NewJWTRequest
// func TestPBFromNewJWTRequest(t *testing.T) {
// 	// TODO : fill me up
// 	payload := NewJWTRequest{

// 		KID:    "",
// 		Claims: []byte{},
// 	}
// 	result := NewPBFromNewJWTRequest(&payload)
// 	assert.Equal(t, payload.KID, result.KID)
// 	assert.Equal(t, payload.Claims, result.Claims)

// }

// // test transformer *pb.NewJWTResponse to *NewJWTResponse
// func TestNewJWTResponseFromPB(t *testing.T) {
// 	// TODO : fill me up
// 	payload := pb.NewJWTResponse{

// 		ID:           "",
// 		AccessToken:  "",
// 		RefreshToken: "",
// 		Expiry:       0,
// 	}
// 	result := NewNewJWTResponseFromPB(&payload)
// 	assert.Equal(t, payload.ID, result.ID)
// 	assert.Equal(t, payload.AccessToken, result.AccessToken)
// 	assert.Equal(t, payload.RefreshToken, result.RefreshToken)
// 	assert.Equal(t, payload.Expiry, result.Expiry)

// }

// // test transformer *NewJWTResponse to *pb.NewJWTResponse
// func TestPBFromNewJWTResponse(t *testing.T) {
// 	// TODO : fill me up
// 	payload := NewJWTResponse{

// 		ID:           "",
// 		AccessToken:  "",
// 		RefreshToken: "",
// 		Expiry:       0,
// 	}
// 	result := NewPBFromNewJWTResponse(&payload)
// 	assert.Equal(t, payload.ID, result.ID)
// 	assert.Equal(t, payload.AccessToken, result.AccessToken)
// 	assert.Equal(t, payload.RefreshToken, result.RefreshToken)
// 	assert.Equal(t, payload.Expiry, result.Expiry)

// }

// // test transformer *pb.RenewJWTRequest to *RenewJWTRequest
// func TestRenewJWTRequestFromPB(t *testing.T) {
// 	// TODO : fill me up
// 	payload := pb.RenewJWTRequest{

// 		KID:             "",
// 		RefreshToken:    "",
// 		RefreshStrategy: "",
// 	}
// 	result := NewRenewJWTRequestFromPB(&payload)
// 	assert.Equal(t, payload.KID, result.KID)
// 	assert.Equal(t, payload.RefreshToken, result.RefreshToken)
// 	assert.Equal(t, payload.RefreshStrategy, result.RefreshStrategy)

// }

// // test transformer *RenewJWTRequest to *pb.RenewJWTRequest
// func TestPBFromRenewJWTRequest(t *testing.T) {
// 	// TODO : fill me up
// 	payload := RenewJWTRequest{

// 		KID:             "",
// 		RefreshToken:    "",
// 		RefreshStrategy: "",
// 	}
// 	result := NewPBFromRenewJWTRequest(&payload)
// 	assert.Equal(t, payload.KID, result.KID)
// 	assert.Equal(t, payload.RefreshToken, result.RefreshToken)
// 	assert.Equal(t, payload.RefreshStrategy, result.RefreshStrategy)

// }

// // test transformer *pb.RenewJWTResponse to *RenewJWTResponse
// func TestRenewJWTResponseFromPB(t *testing.T) {
// 	// TODO : fill me up
// 	payload := pb.RenewJWTResponse{

// 		ID:           "",
// 		AccessToken:  "",
// 		RefreshToken: "",
// 		Expiry:       0,
// 	}
// 	result := NewRenewJWTResponseFromPB(&payload)
// 	assert.Equal(t, payload.ID, result.ID)
// 	assert.Equal(t, payload.AccessToken, result.AccessToken)
// 	assert.Equal(t, payload.RefreshToken, result.RefreshToken)
// 	assert.Equal(t, payload.Expiry, result.Expiry)

// }

// // test transformer *RenewJWTResponse to *pb.RenewJWTResponse
// func TestPBFromRenewJWTResponse(t *testing.T) {
// 	// TODO : fill me up
// 	payload := RenewJWTResponse{

// 		ID:           "",
// 		AccessToken:  "",
// 		RefreshToken: "",
// 		Expiry:       0,
// 	}
// 	result := NewPBFromRenewJWTResponse(&payload)
// 	assert.Equal(t, payload.ID, result.ID)
// 	assert.Equal(t, payload.AccessToken, result.AccessToken)
// 	assert.Equal(t, payload.RefreshToken, result.RefreshToken)
// 	assert.Equal(t, payload.Expiry, result.Expiry)

// }

// // test transformer *pb.RevokeJWTRequest to *RevokeJWTRequest
// func TestRevokeJWTRequestFromPB(t *testing.T) {
// 	// TODO : fill me up
// 	payload := pb.RevokeJWTRequest{

// 		KID:          "",
// 		ID:           "",
// 		RefreshToken: "",
// 	}
// 	result := NewRevokeJWTRequestFromPB(&payload)
// 	assert.Equal(t, payload.KID, result.KID)
// 	assert.Equal(t, payload.ID, result.ID)
// 	assert.Equal(t, payload.RefreshToken, result.RefreshToken)

// }

// // test transformer *RevokeJWTRequest to *pb.RevokeJWTRequest
// func TestPBFromRevokeJWTRequest(t *testing.T) {
// 	// TODO : fill me up
// 	payload := RevokeJWTRequest{

// 		KID:          "",
// 		ID:           "",
// 		RefreshToken: "",
// 	}
// 	result := NewPBFromRevokeJWTRequest(&payload)
// 	assert.Equal(t, payload.KID, result.KID)
// 	assert.Equal(t, payload.ID, result.ID)
// 	assert.Equal(t, payload.RefreshToken, result.RefreshToken)

// }

// // test transformer *pb.RevokeJWTResponse to *RevokeJWTResponse
// func TestRevokeJWTResponseFromPB(t *testing.T) {
// 	// TODO : fill me up
// 	payload := pb.RevokeJWTResponse{}
// 	result := NewRevokeJWTResponseFromPB(&payload)
// 	_ = result // zero fields, nothing to assert
// }

// // test transformer *RevokeJWTResponse to *pb.RevokeJWTResponse
// func TestPBFromRevokeJWTResponse(t *testing.T) {
// 	// TODO : fill me up
// 	payload := RevokeJWTResponse{}
// 	result := NewPBFromRevokeJWTResponse(&payload)
// 	_ = result // zero fields, nothing to assert
// }

// // test transformer *pb.AuthRequest to *AuthRequest
// func TestAuthRequestFromPB(t *testing.T) {
// 	// TODO : fill me up
// 	payload := pb.AuthRequest{

// 		KID: "",
// 	}
// 	result := NewAuthRequestFromPB(&payload)
// 	assert.Equal(t, payload.KID, result.KID)

// }

// // test transformer *AuthRequest to *pb.AuthRequest
// func TestPBFromAuthRequest(t *testing.T) {
// 	// TODO : fill me up
// 	payload := AuthRequest{

// 		KID: "",
// 	}
// 	result := NewPBFromAuthRequest(&payload)
// 	assert.Equal(t, payload.KID, result.KID)

// }

// // test transformer *pb.AuthResponse to *AuthResponse
// func TestAuthResponseFromPB(t *testing.T) {
// 	// TODO : fill me up
// 	payload := pb.AuthResponse{

// 		AuthJWT: "",
// 	}
// 	result := NewAuthResponseFromPB(&payload)
// 	assert.Equal(t, payload.AuthJWT, result.AuthJWT)

// }

// // test transformer *AuthResponse to *pb.AuthResponse
// func TestPBFromAuthResponse(t *testing.T) {
// 	// TODO : fill me up
// 	payload := AuthResponse{

// 		AuthJWT: "",
// 	}
// 	result := NewPBFromAuthResponse(&payload)
// 	assert.Equal(t, payload.AuthJWT, result.AuthJWT)

// }

// // test transformer *pb.RegisterRequest to *RegisterRequest
// func TestRegisterRequestFromPB(t *testing.T) {
// 	// TODO : fill me up
// 	payload := pb.RegisterRequest{

// 		KID:             "",
// 		Expiry:          0,
// 		SigAlg:          "",
// 		SigBits:         0,
// 		EncAlg:          "",
// 		EncBits:         0,
// 		AuthTTL:         0,
// 		RefreshTTL:      0,
// 		RefreshStrategy: "",
// 	}
// 	result := NewRegisterRequestFromPB(&payload)
// 	assert.Equal(t, payload.KID, result.KID)
// 	assert.Equal(t, payload.Expiry, result.Expiry)
// 	assert.Equal(t, payload.SigAlg, result.SigAlg)
// 	assert.Equal(t, payload.SigBits, result.SigBits)
// 	assert.Equal(t, payload.EncAlg, result.EncAlg)
// 	assert.Equal(t, payload.EncBits, result.EncBits)
// 	assert.Equal(t, payload.AuthTTL, result.AuthTTL)
// 	assert.Equal(t, payload.RefreshTTL, result.RefreshTTL)
// 	assert.Equal(t, payload.RefreshStrategy, result.RefreshStrategy)

// }

// // test transformer *RegisterRequest to *pb.RegisterRequest
// func TestPBFromRegisterRequest(t *testing.T) {
// 	// TODO : fill me up
// 	payload := RegisterRequest{

// 		KID:             "",
// 		Expiry:          0,
// 		SigAlg:          "",
// 		SigBits:         0,
// 		EncAlg:          "",
// 		EncBits:         0,
// 		AuthTTL:         0,
// 		RefreshTTL:      0,
// 		RefreshStrategy: "",
// 	}
// 	result := NewPBFromRegisterRequest(&payload)
// 	assert.Equal(t, payload.KID, result.KID)
// 	assert.Equal(t, payload.Expiry, result.Expiry)
// 	assert.Equal(t, payload.SigAlg, result.SigAlg)
// 	assert.Equal(t, payload.SigBits, result.SigBits)
// 	assert.Equal(t, payload.EncAlg, result.EncAlg)
// 	assert.Equal(t, payload.EncBits, result.EncBits)
// 	assert.Equal(t, payload.AuthTTL, result.AuthTTL)
// 	assert.Equal(t, payload.RefreshTTL, result.RefreshTTL)
// 	assert.Equal(t, payload.RefreshStrategy, result.RefreshStrategy)

// }

// // test transformer *pb.RegisterResponse to *RegisterResponse
// func TestRegisterResponseFromPB(t *testing.T) {
// 	// TODO : fill me up
// 	payload := pb.RegisterResponse{

// 		KID:             "",
// 		AuthJWT:         "",
// 		PubSigKey:       []byte{},
// 		PubEncKey:       []byte{},
// 		Expiry:          0,
// 		Valid:           false,
// 		RefreshStrategy: "",
// 	}
// 	result := NewRegisterResponseFromPB(&payload)
// 	assert.Equal(t, payload.KID, result.KID)
// 	assert.Equal(t, payload.AuthJWT, result.AuthJWT)
// 	assert.Equal(t, payload.PubSigKey, result.PubSigKey)
// 	assert.Equal(t, payload.PubEncKey, result.PubEncKey)
// 	assert.Equal(t, payload.Expiry, result.Expiry)
// 	assert.Equal(t, payload.Valid, result.Valid)
// 	assert.Equal(t, payload.RefreshStrategy, result.RefreshStrategy)

// }

// // test transformer *RegisterResponse to *pb.RegisterResponse
// func TestPBFromRegisterResponse(t *testing.T) {
// 	// TODO : fill me up
// 	payload := RegisterResponse{

// 		KID:             "",
// 		AuthJWT:         "",
// 		PubSigKey:       []byte{},
// 		PubEncKey:       []byte{},
// 		Expiry:          0,
// 		Valid:           false,
// 		RefreshStrategy: "",
// 	}
// 	result := NewPBFromRegisterResponse(&payload)
// 	assert.Equal(t, payload.KID, result.KID)
// 	assert.Equal(t, payload.AuthJWT, result.AuthJWT)
// 	assert.Equal(t, payload.PubSigKey, result.PubSigKey)
// 	assert.Equal(t, payload.PubEncKey, result.PubEncKey)
// 	assert.Equal(t, payload.Expiry, result.Expiry)
// 	assert.Equal(t, payload.Valid, result.Valid)
// 	assert.Equal(t, payload.RefreshStrategy, result.RefreshStrategy)

// }

// // test transformer *pb.UpdateKeysRequest to *UpdateKeysRequest
// func TestUpdateKeysRequestFromPB(t *testing.T) {
// 	// TODO : fill me up
// 	payload := pb.UpdateKeysRequest{

// 		KID:             "",
// 		Expiry:          0,
// 		SigAlg:          "",
// 		SigBits:         0,
// 		EncAlg:          "",
// 		EncBits:         0,
// 		AuthTTL:         0,
// 		RefreshTTL:      0,
// 		RefreshStrategy: "",
// 	}
// 	result := NewUpdateKeysRequestFromPB(&payload)
// 	assert.Equal(t, payload.KID, result.KID)
// 	assert.Equal(t, payload.Expiry, result.Expiry)
// 	assert.Equal(t, payload.SigAlg, result.SigAlg)
// 	assert.Equal(t, payload.SigBits, result.SigBits)
// 	assert.Equal(t, payload.EncAlg, result.EncAlg)
// 	assert.Equal(t, payload.EncBits, result.EncBits)
// 	assert.Equal(t, payload.AuthTTL, result.AuthTTL)
// 	assert.Equal(t, payload.RefreshTTL, result.RefreshTTL)
// 	assert.Equal(t, payload.RefreshStrategy, result.RefreshStrategy)

// }

// // test transformer *UpdateKeysRequest to *pb.UpdateKeysRequest
// func TestPBFromUpdateKeysRequest(t *testing.T) {
// 	// TODO : fill me up
// 	payload := UpdateKeysRequest{

// 		KID:             "",
// 		Expiry:          0,
// 		SigAlg:          "",
// 		SigBits:         0,
// 		EncAlg:          "",
// 		EncBits:         0,
// 		AuthTTL:         0,
// 		RefreshTTL:      0,
// 		RefreshStrategy: "",
// 	}
// 	result := NewPBFromUpdateKeysRequest(&payload)
// 	assert.Equal(t, payload.KID, result.KID)
// 	assert.Equal(t, payload.Expiry, result.Expiry)
// 	assert.Equal(t, payload.SigAlg, result.SigAlg)
// 	assert.Equal(t, payload.SigBits, result.SigBits)
// 	assert.Equal(t, payload.EncAlg, result.EncAlg)
// 	assert.Equal(t, payload.EncBits, result.EncBits)
// 	assert.Equal(t, payload.AuthTTL, result.AuthTTL)
// 	assert.Equal(t, payload.RefreshTTL, result.RefreshTTL)
// 	assert.Equal(t, payload.RefreshStrategy, result.RefreshStrategy)

// }

// // test transformer *pb.UpdateKeysResponse to *UpdateKeysResponse
// func TestUpdateKeysResponseFromPB(t *testing.T) {
// 	// TODO : fill me up
// 	payload := pb.UpdateKeysResponse{

// 		KID:             "",
// 		AuthJWT:         "",
// 		PubSigKey:       []byte{},
// 		PubEncKey:       []byte{},
// 		Expiry:          0,
// 		Valid:           false,
// 		RefreshStrategy: "",
// 	}
// 	result := NewUpdateKeysResponseFromPB(&payload)
// 	assert.Equal(t, payload.KID, result.KID)
// 	assert.Equal(t, payload.AuthJWT, result.AuthJWT)
// 	assert.Equal(t, payload.PubSigKey, result.PubSigKey)
// 	assert.Equal(t, payload.PubEncKey, result.PubEncKey)
// 	assert.Equal(t, payload.Expiry, result.Expiry)
// 	assert.Equal(t, payload.Valid, result.Valid)
// 	assert.Equal(t, payload.RefreshStrategy, result.RefreshStrategy)

// }

// // test transformer *UpdateKeysResponse to *pb.UpdateKeysResponse
// func TestPBFromUpdateKeysResponse(t *testing.T) {
// 	// TODO : fill me up
// 	payload := UpdateKeysResponse{

// 		KID:             "",
// 		AuthJWT:         "",
// 		PubSigKey:       []byte{},
// 		PubEncKey:       []byte{},
// 		Expiry:          0,
// 		Valid:           false,
// 		RefreshStrategy: "",
// 	}
// 	result := NewPBFromUpdateKeysResponse(&payload)
// 	assert.Equal(t, payload.KID, result.KID)
// 	assert.Equal(t, payload.AuthJWT, result.AuthJWT)
// 	assert.Equal(t, payload.PubSigKey, result.PubSigKey)
// 	assert.Equal(t, payload.PubEncKey, result.PubEncKey)
// 	assert.Equal(t, payload.Expiry, result.Expiry)
// 	assert.Equal(t, payload.Valid, result.Valid)
// 	assert.Equal(t, payload.RefreshStrategy, result.RefreshStrategy)

// }

// // test transformer *pb.ListKeysRequest to *ListKeysRequest
// func TestListKeysRequestFromPB(t *testing.T) {
// 	// TODO : fill me up
// 	payload := pb.ListKeysRequest{

// 		Query: "",
// 	}
// 	result := NewListKeysRequestFromPB(&payload)
// 	assert.Equal(t, payload.Query, result.Query)

// }

// // test transformer *ListKeysRequest to *pb.ListKeysRequest
// func TestPBFromListKeysRequest(t *testing.T) {
// 	// TODO : fill me up
// 	payload := ListKeysRequest{

// 		Query: "",
// 	}
// 	result := NewPBFromListKeysRequest(&payload)
// 	assert.Equal(t, payload.Query, result.Query)

// }

// // test transformer *pb.ListKeysResponse to *ListKeysResponse
// func TestListKeysResponseFromPB(t *testing.T) {
// 	// TODO : fill me up
// 	payload := pb.ListKeysResponse{

// 		KID:             "",
// 		Expiry:          0,
// 		AuthTTL:         0,
// 		RefreshTTL:      0,
// 		RefreshStrategy: "",
// 		PubSigKey:       []byte{},
// 		PubEncKey:       []byte{},
// 		Locked:          false,
// 		Valid:           false,
// 		Expired:         false,
// 	}
// 	result := NewListKeysResponseFromPB(&payload)
// 	assert.Equal(t, payload.KID, result.KID)
// 	assert.Equal(t, payload.Expiry, result.Expiry)
// 	assert.Equal(t, payload.AuthTTL, result.AuthTTL)
// 	assert.Equal(t, payload.RefreshTTL, result.RefreshTTL)
// 	assert.Equal(t, payload.RefreshStrategy, result.RefreshStrategy)
// 	assert.Equal(t, payload.PubSigKey, result.PubSigKey)
// 	assert.Equal(t, payload.PubEncKey, result.PubEncKey)
// 	assert.Equal(t, payload.Locked, result.Locked)
// 	assert.Equal(t, payload.Valid, result.Valid)
// 	assert.Equal(t, payload.Expired, result.Expired)

// }

// // test transformer *ListKeysResponse to *pb.ListKeysResponse
// func TestPBFromListKeysResponse(t *testing.T) {
// 	// TODO : fill me up
// 	payload := ListKeysResponse{

// 		KID:             "",
// 		Expiry:          0,
// 		AuthTTL:         0,
// 		RefreshTTL:      0,
// 		RefreshStrategy: "",
// 		PubSigKey:       []byte{},
// 		PubEncKey:       []byte{},
// 		Locked:          false,
// 		Valid:           false,
// 		Expired:         false,
// 	}
// 	result := NewPBFromListKeysResponse(&payload)
// 	assert.Equal(t, payload.KID, result.KID)
// 	assert.Equal(t, payload.Expiry, result.Expiry)
// 	assert.Equal(t, payload.AuthTTL, result.AuthTTL)
// 	assert.Equal(t, payload.RefreshTTL, result.RefreshTTL)
// 	assert.Equal(t, payload.RefreshStrategy, result.RefreshStrategy)
// 	assert.Equal(t, payload.PubSigKey, result.PubSigKey)
// 	assert.Equal(t, payload.PubEncKey, result.PubEncKey)
// 	assert.Equal(t, payload.Locked, result.Locked)
// 	assert.Equal(t, payload.Valid, result.Valid)
// 	assert.Equal(t, payload.Expired, result.Expired)

// }

// // test transformer *pb.DelKeysRequest to *DelKeysRequest
// func TestDelKeysRequestFromPB(t *testing.T) {
// 	// TODO : fill me up
// 	payload := pb.DelKeysRequest{

// 		KID: "",
// 	}
// 	result := NewDelKeysRequestFromPB(&payload)
// 	assert.Equal(t, payload.KID, result.KID)

// }

// // test transformer *DelKeysRequest to *pb.DelKeysRequest
// func TestPBFromDelKeysRequest(t *testing.T) {
// 	// TODO : fill me up
// 	payload := DelKeysRequest{

// 		KID: "",
// 	}
// 	result := NewPBFromDelKeysRequest(&payload)
// 	assert.Equal(t, payload.KID, result.KID)

// }

// // test transformer *pb.DelKeysResponse to *DelKeysResponse
// func TestDelKeysResponseFromPB(t *testing.T) {
// 	// TODO : fill me up
// 	payload := pb.DelKeysResponse{}
// 	result := NewDelKeysResponseFromPB(&payload)
// 	_ = result // zero fields, nothing to assert
// }

// // test transformer *DelKeysResponse to *pb.DelKeysResponse
// func TestPBFromDelKeysResponse(t *testing.T) {
// 	// TODO : fill me up
// 	payload := DelKeysResponse{}
// 	result := NewPBFromDelKeysResponse(&payload)
// 	_ = result // zero fields, nothing to assert
// }

// // test transformer *pb.PublicKeysRequest to *PublicKeysRequest
// func TestPublicKeysRequestFromPB(t *testing.T) {
// 	// TODO : fill me up
// 	payload := pb.PublicKeysRequest{

// 		KID: "",
// 	}
// 	result := NewPublicKeysRequestFromPB(&payload)
// 	assert.Equal(t, payload.KID, result.KID)

// }

// // test transformer *PublicKeysRequest to *pb.PublicKeysRequest
// func TestPBFromPublicKeysRequest(t *testing.T) {
// 	// TODO : fill me up
// 	payload := PublicKeysRequest{

// 		KID: "",
// 	}
// 	result := NewPBFromPublicKeysRequest(&payload)
// 	assert.Equal(t, payload.KID, result.KID)

// }

// // test transformer *pb.PublicKeysResponse to *PublicKeysResponse
// func TestPublicKeysResponseFromPB(t *testing.T) {
// 	// TODO : fill me up
// 	payload := pb.PublicKeysResponse{

// 		KID:       "",
// 		PubSigKey: []byte{},
// 		PubEncKey: []byte{},
// 		Expiry:    0,
// 		Valid:     false,
// 	}
// 	result := NewPublicKeysResponseFromPB(&payload)
// 	assert.Equal(t, payload.KID, result.KID)
// 	assert.Equal(t, payload.PubSigKey, result.PubSigKey)
// 	assert.Equal(t, payload.PubEncKey, result.PubEncKey)
// 	assert.Equal(t, payload.Expiry, result.Expiry)
// 	assert.Equal(t, payload.Valid, result.Valid)

// }

// // test transformer *PublicKeysResponse to *pb.PublicKeysResponse
// func TestPBFromPublicKeysResponse(t *testing.T) {
// 	// TODO : fill me up
// 	payload := PublicKeysResponse{

// 		KID:       "",
// 		PubSigKey: []byte{},
// 		PubEncKey: []byte{},
// 		Expiry:    0,
// 		Valid:     false,
// 	}
// 	result := NewPBFromPublicKeysResponse(&payload)
// 	assert.Equal(t, payload.KID, result.KID)
// 	assert.Equal(t, payload.PubSigKey, result.PubSigKey)
// 	assert.Equal(t, payload.PubEncKey, result.PubEncKey)
// 	assert.Equal(t, payload.Expiry, result.Expiry)
// 	assert.Equal(t, payload.Valid, result.Valid)

// }

// // test transformer *pb.PingRequest to *PingRequest
// func TestPingRequestFromPB(t *testing.T) {
// 	// TODO : fill me up
// 	payload := pb.PingRequest{}
// 	result := NewPingRequestFromPB(&payload)
// 	_ = result // zero fields, nothing to assert
// }

// // test transformer *PingRequest to *pb.PingRequest
// func TestPBFromPingRequest(t *testing.T) {
// 	// TODO : fill me up
// 	payload := PingRequest{}
// 	result := NewPBFromPingRequest(&payload)
// 	_ = result // zero fields, nothing to assert
// }

// // test transformer *pb.PingResponse to *PingResponse
// func TestPingResponseFromPB(t *testing.T) {
// 	// TODO : fill me up
// 	payload := pb.PingResponse{

// 		Status: "",
// 	}
// 	result := NewPingResponseFromPB(&payload)
// 	assert.Equal(t, payload.Status, result.Status)

// }

// // test transformer *PingResponse to *pb.PingResponse
// func TestPBFromPingResponse(t *testing.T) {
// 	// TODO : fill me up
// 	payload := PingResponse{

// 		Status: "",
// 	}
// 	result := NewPBFromPingResponse(&payload)
// 	assert.Equal(t, payload.Status, result.Status)

// }

// // test transformer *pb.ReadyRequest to *ReadyRequest
// func TestReadyRequestFromPB(t *testing.T) {
// 	// TODO : fill me up
// 	payload := pb.ReadyRequest{}
// 	result := NewReadyRequestFromPB(&payload)
// 	_ = result // zero fields, nothing to assert
// }

// // test transformer *ReadyRequest to *pb.ReadyRequest
// func TestPBFromReadyRequest(t *testing.T) {
// 	// TODO : fill me up
// 	payload := ReadyRequest{}
// 	result := NewPBFromReadyRequest(&payload)
// 	_ = result // zero fields, nothing to assert
// }

// // test transformer *pb.ReadyResponse to *ReadyResponse
// func TestReadyResponseFromPB(t *testing.T) {
// 	// TODO : fill me up
// 	payload := pb.ReadyResponse{

// 		Status: "",
// 		Start:  0,
// 		Up:     0,
// 	}
// 	result := NewReadyResponseFromPB(&payload)
// 	assert.Equal(t, payload.Status, result.Status)
// 	assert.Equal(t, payload.Start, result.Start)
// 	assert.Equal(t, payload.Up, result.Up)

// }

// // test transformer *ReadyResponse to *pb.ReadyResponse
// func TestPBFromReadyResponse(t *testing.T) {
// 	// TODO : fill me up
// 	payload := ReadyResponse{

// 		Status: "",
// 		Start:  0,
// 		Up:     0,
// 	}
// 	result := NewPBFromReadyResponse(&payload)
// 	assert.Equal(t, payload.Status, result.Status)
// 	assert.Equal(t, payload.Start, result.Start)
// 	assert.Equal(t, payload.Up, result.Up)

// }
