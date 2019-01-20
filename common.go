package jwtis

// Code is copied from https://github.com/ory/hydra
// and https://github.com/ory/x/randx repos

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	bolt "github.com/coreos/bbolt"
)

var secretCharSet = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.~!{}[]&?@#$&*()")

// GenerateSecret gererates a secret including chars from secret char set
func GenerateSecret(length int) ([]byte, error) {
	secret, err := RuneSequence(length, secretCharSet)
	if err != nil {
		return []byte{}, err
	}
	return []byte(string(secret)), nil
}

var rander = rand.Reader // random function

var (
	// AlphaNum contains runes [abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789].
	AlphaNum = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	// Alpha contains runes [abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ].
	Alpha = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	// AlphaLowerNum contains runes [abcdefghijklmnopqrstuvwxyz0123456789].
	AlphaLowerNum = []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	// AlphaUpperNum contains runes [ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789].
	AlphaUpperNum = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	// AlphaLower contains runes [abcdefghijklmnopqrstuvwxyz].
	AlphaLower = []rune("abcdefghijklmnopqrstuvwxyz")
	// AlphaUpper contains runes [ABCDEFGHIJKLMNOPQRSTUVWXYZ].
	AlphaUpper = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	// Numeric contains runes [0123456789].
	Numeric = []rune("0123456789")
)

// RuneSequence returns a random sequence using the defined allowed runes.
func RuneSequence(l int, allowedRunes []rune) (seq []rune, err error) {
	c := big.NewInt(int64(len(allowedRunes)))
	seq = make([]rune, l)

	for i := 0; i < l; i++ {
		r, err := rand.Int(rander, c)
		if err != nil {
			return seq, err
		}
		rn := allowedRunes[r.Uint64()]
		seq[i] = rn
	}

	return seq, nil
}

// Error implements multierror type
type Error []error

// Error implements error interface
func (mr Error) Error() string {
	if mr == nil {
		return ""
	}

	strs := make([]string, len(mr))
	for i, err := range mr {
		strs[i] = fmt.Sprintf("%v; ", err)
	}
	return strings.Join(strs, "")
}

// Append appends errors to array if err != nil
func (mr *Error) Append(errs ...error) Error {
	if mr == nil {
		*mr = []error{}
	}
	for i := range errs {
		if errs[i] != nil {
			*mr = append(*mr, errs[i])
		}
	}
	return *mr
}

// SaveSealed saves marshaled value to key for bucket. Should run in update tx
func SaveSealed(encKey *Key, nonce []byte, bkt *bolt.Bucket, key []byte, value interface{}) (err error) {
	if value == nil {
		return fmt.Errorf("can't save nil value for %s", string(key))
	}
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("can't marshal value: %s", err.Error())
	}
	buf := make([]byte, 0, len(data)+Extension)
	ciphertext := encKey.Seal(buf[:0], nonce, data, nil)
	if err = bkt.Put(key, ciphertext); err != nil {
		return fmt.Errorf("failed to save key %s, error: %s", string(key), err.Error())
	}
	return nil
}

// LoadSealed loads and unmarshals json value by key from bucket. Should run in view tx
func LoadSealed(encKey *Key, nonce []byte, bkt *bolt.Bucket, key []byte, res interface{}) error {
	plaintext := bkt.Get(key)
	if plaintext == nil {
		return ErrKeyNotFound
	}
	buf := make([]byte, 0, len(plaintext))
	value, err := encKey.Open(buf, nonce, plaintext, nil)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(value, &res); err != nil {
		return fmt.Errorf("failed to unmarshal: %s", err.Error())
	}
	return nil
}
