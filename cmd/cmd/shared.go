package cmd

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"io"

	"golang.org/x/crypto/hkdf"
)

var (
	// encodeBytes is default variable for password encoding func
	encodeBytes = base64Encode
	// decodeBytes is default variable for password decoding func
	decodeBytes = base64Decode
)

func newPassword() ([32]byte, error) {
	pswd := [32]byte{}
	l, err := rand.Read(pswd[:])
	if err != nil || l != 32 {
		return pswd, fmt.Errorf("error get new password: %s", err.Error())
	}
	derived, err := deriveKey(pswd[:])
	if err != nil || len(derived) != 32 {
		return pswd, fmt.Errorf("error secure new password: %s", err.Error())
	}
	copy(pswd[:], derived)
	for i := range derived {
		derived[i] = 0
	}
	return pswd, nil
}

func base64Encode(src []byte) []byte {
	dst := make([]byte, base64.RawURLEncoding.EncodedLen(len(src)))
	base64.RawURLEncoding.Encode(dst, src)
	return dst
}

func base64Decode(src []byte) ([]byte, error) {
	dst := make([]byte, base64.RawURLEncoding.DecodedLen(len(src)))
	n, err := base64.RawURLEncoding.Decode(dst, src)
	if err != nil || n != len(dst) {
		return nil, fmt.Errorf("error base64 decode: %s", err.Error())
	}
	return dst, nil
}

func hexEncode(src []byte) []byte {
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	return dst
}

func hexDecode(src []byte) ([]byte, error) {
	dst := make([]byte, hex.DecodedLen(len(src)))
	n, err := hex.Decode(dst, src)
	if err != nil || n != len(dst) {
		return nil, fmt.Errorf("error hex decode: %s", err.Error())
	}
	return dst, nil
}

func deriveKey(masterkey []byte) ([]byte, error) {
	var nonce [32]byte
	if n, err := io.ReadFull(rand.Reader, nonce[:]); err != nil || n != 32 {
		return nil, fmt.Errorf("error key derivation, no nonce was got")
	}

	// derive an encryption key from the master key and the nonce
	var key [32]byte
	kdf := hkdf.New(sha256.New, masterkey, nonce[:], nil)
	if n, err := io.ReadFull(kdf, key[:]); err != nil || n != 32 {
		return nil, fmt.Errorf("error key derivation, no key was derived")
	}
	return key[:], nil
}
