package jwtis

import (
	"fmt"

	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

// ClaimsSignedAndEncrypted takes claims from encrypted and signed string jwt
func ClaimsSignedAndEncrypted(enckey *jose.JSONWebKey, sigkey *jose.JSONWebKey,
	raw string, dest ...interface{}) error {
	if !enckey.IsPublic() {
		pubEncKey := enckey.Public()
		enckey = &pubEncKey
	}
	if !sigkey.IsPublic() {
		pubSigKey := sigkey.Public()
		sigkey = &pubSigKey
	}
	tok, err := jwt.ParseSignedAndEncrypted(raw)
	if err != nil {
		return fmt.Errorf("error ParseSignedAndEncrypted raw jwt: %s", err.Error())
	}

	nested, err := tok.Decrypt(enckey)
	if err != nil {
		return fmt.Errorf("error Decrypt parsed jwt: %s", err.Error())
	}

	if err := nested.Claims(sigkey, dest...); err != nil {
		return fmt.Errorf("error get Claims from decrypted jwt: %s", err.Error())
	}
	return nil
}

// ClaimsSigned takes claims from signed string jwt
func ClaimsSigned(sigkey *jose.JSONWebKey,
	raw string, dest ...interface{}) error {
	if !sigkey.IsPublic() {
		pubSigKey := sigkey.Public()
		sigkey = &pubSigKey
	}
	tok, err := jwt.ParseSigned(raw)
	if err != nil {
		return fmt.Errorf("error ParseSigned raw jwt: %s", err.Error())
	}

	if err := tok.Claims(sigkey, dest...); err != nil {
		return fmt.Errorf("error get Claims from parsed jwt: %s", err.Error())
	}
	return nil
}

// JWTSignedAndEncrypted ecryptes and signes claims, returns jwt token string and error
func JWTSignedAndEncrypted(enckey *jose.JSONWebKey, sigkey *jose.JSONWebKey,
	claims ...interface{}) (string, error) {
	enc, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{
			Algorithm: jose.DIRECT,
			Key:       enckey,
		},
		(&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"))
	if err != nil {
		return "", fmt.Errorf("error make new encrypter to encrypt jwt: %s", err.Error())
	}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(sigkey.Algorithm), Key: sigkey.Key}, nil)
	if err != nil {
		return "", fmt.Errorf("error make new signer to sign jwt: %s", err.Error())
	}
	bldr := jwt.SignedAndEncrypted(sig, enc)
	for i := range claims {
		bldr = bldr.Claims(claims[i])
	}
	raw, err := bldr.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("error serializing signed and encrypted jwt: %s", err.Error())
	}
	return raw, nil
}

// JWTSigned signes claims, returns jwt token string and error
func JWTSigned(sigkey *jose.JSONWebKey, claims ...interface{}) (string, error) {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(sigkey.Algorithm), Key: sigkey.Key}, nil)
	if err != nil {
		return "", fmt.Errorf("error make new signer to sign jwt: %s", err.Error())
	}
	bldr := jwt.Signed(sig)
	for i := range claims {
		bldr = bldr.Claims(claims[i])
	}

	raw, err := bldr.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("error serializing signed jwt: %s", err.Error())
	}

	return raw, nil
}
