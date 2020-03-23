package service

import (
	errors "github.com/luno/jettison/errors"
	"github.com/luno/jettison/j"
)

var (
	// ErrInvalidClaimsIssuerCode code
	ErrInvalidClaimsIssuerCode = j.C("ErrInvalidClaimsIssuer")
	// ErrInvalidClaimsExpiryCode code
	ErrInvalidClaimsExpiryCode = j.C("ErrInvalidClaimsExpiry")
	// ErrKIDNotExistsCode code
	ErrKIDNotExistsCode = j.C("ErrKIDNotExists")
	// ErrRefreshTokenExpiredCode code
	ErrRefreshTokenExpiredCode = j.C("ErrRefreshTokenExpired")
	// ErrInvalidRefreshClaimsCode code
	ErrInvalidRefreshClaimsCode = j.C("ErrInvalidRefreshClaims")
	// ErrDecryptRefreshTokenCode code
	ErrDecryptRefreshTokenCode = j.C("ErrDecryptRefreshToken")
	// ErrInternalCode code
	ErrInternalCode = j.C("ErrInternal")
	// UnimplementedCode error code
	UnimplementedCode = j.C("unimplemented method")
	// ErrInvalidClaimsIssuer if kid in new jwt request is not equal to request claims
	ErrInvalidClaimsIssuer = errors.New("claims issuer field is not equal to request kid", ErrInvalidClaimsIssuerCode)
	// ErrInvalidClaimsExpiry if claims expiry is expired already
	ErrInvalidClaimsExpiry = errors.New("claims expiry field is invalid", ErrInvalidClaimsExpiryCode)
	// ErrKIDNotExists if kid is not in boltdb
	ErrKIDNotExists = errors.New("enc, sig keys are not found", ErrKIDNotExistsCode)
	// ErrRefreshTokenExpired error
	ErrRefreshTokenExpired = errors.New("refresh token is expired", ErrRefreshTokenExpiredCode)
	// ErrInvalidRefreshClaims error
	ErrInvalidRefreshClaims = errors.New("refresh token claim are invalid", ErrInvalidRefreshClaimsCode)
	// ErrDecryptRefreshToken err
	ErrDecryptRefreshToken = errors.New("refresh token couldn't be decrypted", ErrDecryptRefreshTokenCode)
	// ErrInternal err
	ErrInternal = errors.New("internal error", ErrInternalCode)
	// ErrUnimplementedMethod error
	ErrUnimplementedMethod = errors.New("unimplemented method", UnimplementedCode)
	// ErrInvalidKeysRepoCode error code
	ErrInvalidKeysRepoCode = j.C("ErrInvalidKeysRepo")
	// ErrInvalidKeysRepo error
	ErrInvalidKeysRepo = errors.New("keyservice pointer is nil", ErrInvalidKeysRepoCode)
	// ErrInvalidOptionsCode error code
	ErrInvalidOptionsCode = j.C("ErrInvalidOptions")
	// ErrInvalidOptions error
	ErrInvalidOptions = errors.New("keyservice pointer is nil", ErrInvalidOptionsCode)
)
