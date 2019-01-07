package jwtis

// Code is copied from https://github.com/ory/hydra
// and https://github.com/ory/x/randx repos

import (
	"crypto/rand"
	"math/big"
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
