package jwtis_test

import (
	"testing"
	"time"

	"github.com/karantin2020/jwtis"
	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

var sigKeys, encKeys, _ = genKeysList()
var sigToks, sigEncToks = genJWTString()

var claims = jwt.Claims{
	Expiry:   jwt.NewNumericDate(time.Now().Add(3 * time.Hour)),
	IssuedAt: jwt.NewNumericDate(time.Now()),
	Subject:  "test_web_client",
	Audience: []string{"example.com", "ya.ru"},
}
var claimsS = jwt.Claims{}

func benchmarkSig(i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		jwtis.JWTSigned(&(sigKeys[i][0]), &claims)
	}
}

func benchmarkSigClaims(i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		jwtis.ClaimsSigned(&(sigKeys[i][1]), sigToks[i], &claimsS)
	}
}

func benchmarkSigEnc(i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		jwtis.JWTSignedAndEncrypted(jose.A128GCM, &(encKeys[i][1]), &(sigKeys[7][0]), &claims)
	}
}

func benchmarkSigEncClaims(i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		jwtis.ClaimsSignedAndEncrypted(&(encKeys[i][0]), &(sigKeys[7][1]), sigEncToks[1], &claimsS)
	}
}

// func BenchmarkFib1(b *testing.B)  { benchmarkFib(1, b) }

func BenchmarkSigRS256(b *testing.B) {
	benchmarkSig(0, b)
}
func BenchmarkSigRS384(b *testing.B) {
	benchmarkSig(1, b)
}
func BenchmarkSigRS512(b *testing.B) {
	benchmarkSig(2, b)
}
func BenchmarkSigPS256(b *testing.B) {
	benchmarkSig(3, b)
}
func BenchmarkSigPS384(b *testing.B) {
	benchmarkSig(4, b)
}
func BenchmarkSigPS512(b *testing.B) {
	benchmarkSig(5, b)
}
func BenchmarkSigES256(b *testing.B) {
	benchmarkSig(6, b)
}
func BenchmarkSigES384(b *testing.B) {
	benchmarkSig(7, b)
}
func BenchmarkSigES512(b *testing.B) {
	benchmarkSig(8, b)
}
func BenchmarkSigEdDSA(b *testing.B) {
	benchmarkSig(9, b)
}

// Get claim sig tests

func BenchmarkSigClaimsRS256(b *testing.B) {
	benchmarkSigClaims(0, b)
}
func BenchmarkSigClaimsRS384(b *testing.B) {
	benchmarkSigClaims(1, b)
}
func BenchmarkSigClaimsRS512(b *testing.B) {
	benchmarkSigClaims(2, b)
}
func BenchmarkSigClaimsPS256(b *testing.B) {
	benchmarkSigClaims(3, b)
}
func BenchmarkSigClaimsPS384(b *testing.B) {
	benchmarkSigClaims(4, b)
}
func BenchmarkSigClaimsPS512(b *testing.B) {
	benchmarkSigClaims(5, b)
}
func BenchmarkSigClaimsES256(b *testing.B) {
	benchmarkSigClaims(6, b)
}
func BenchmarkSigClaimsES384(b *testing.B) {
	benchmarkSigClaims(7, b)
}
func BenchmarkSigClaimsES512(b *testing.B) {
	benchmarkSigClaims(8, b)
}
func BenchmarkSigClaimsEdDSA(b *testing.B) {
	benchmarkSigClaims(9, b)
}

// SigEnc make JWT bench tests
func BenchmarkSigEncRSA1_5(b *testing.B) {
	benchmarkSigEnc(0, b)
}
func BenchmarkSigEncRSA_OAEP(b *testing.B) {
	benchmarkSigEnc(1, b)
}
func BenchmarkSigEncRSA_OAEP_256(b *testing.B) {
	benchmarkSigEnc(2, b)
}
func BenchmarkSigEncECDH_ES(b *testing.B) {
	benchmarkSigEnc(3, b)
}
func BenchmarkSigEncECDH_ES_A128KW(b *testing.B) {
	benchmarkSigEnc(4, b)
}
func BenchmarkSigEncECDH_ES_A192KW(b *testing.B) {
	benchmarkSigEnc(5, b)
}
func BenchmarkSigEncECDH_ES_A256KW(b *testing.B) {
	benchmarkSigEnc(6, b)
}

// Bench test sig enc claims

func BenchmarkSigEncClaimsRSA1_5(b *testing.B) {
	benchmarkSigEncClaims(0, b)
}
func BenchmarkSigEncClaimsRSA_OAEP(b *testing.B) {
	benchmarkSigEncClaims(1, b)
}
func BenchmarkSigEncClaimsRSA_OAEP_256(b *testing.B) {
	benchmarkSigEncClaims(2, b)
}
func BenchmarkSigEncClaimsECDH_ES(b *testing.B) {
	benchmarkSigEncClaims(3, b)
}
func BenchmarkSigEncClaimsECDH_ES_A128KW(b *testing.B) {
	benchmarkSigEncClaims(4, b)
}
func BenchmarkSigEncClaimsECDH_ES_A192KW(b *testing.B) {
	benchmarkSigEncClaims(5, b)
}
func BenchmarkSigEncClaimsECDH_ES_A256KW(b *testing.B) {
	benchmarkSigEncClaims(6, b)
}

var (
	sigAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
	encAlgs = []string{"RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"}
)

func genKeys(alg, use string) ([2]jose.JSONWebKey, error) {
	bits := 0
	switch alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		bits = 2048
	case "ES256", "ES384", "ES512", "EdDSA":
		bits = 0
	default:

	}
	priv, pub, err := jwtis.GenerateKeys("test"+alg, jwtis.KeyOptions{
		Use:  use,
		Alg:  alg,
		Bits: bits,
	})
	return [2]jose.JSONWebKey{priv, pub}, err
}

func genKeysList() ([][2]jose.JSONWebKey, [][2]jose.JSONWebKey, error) {
	var mErr jwtis.Error
	sig := make([][2]jose.JSONWebKey, 0, 10)
	enc := make([][2]jose.JSONWebKey, 0, 7)

	for i := range sigAlgs {
		keys, err := genKeys(sigAlgs[i], "sig")
		if err != nil {
			mErr.Append(err)
			continue
		}
		sig = append(sig, keys)
	}
	for i := range encAlgs {
		keys, err := genKeys(encAlgs[i], "enc")
		if err != nil {
			mErr.Append(err)
			continue
		}
		enc = append(enc, keys)
	}
	return sig, enc, mErr
}

func genJWTString() ([]string, []string) {
	var mErr jwtis.Error
	sig := make([]string, 0, 10)
	enc := make([]string, 0, 7)

	for i := range sigAlgs {
		js, err := jwtis.JWTSigned(&(sigKeys[i][0]), &claims)
		if err != nil {
			mErr.Append(err)
			continue
		}
		sig = append(sig, js)
	}
	for i := range encAlgs {
		jse, err := jwtis.JWTSignedAndEncrypted(jose.A128GCM, &(encKeys[i][1]), &(sigKeys[7][0]), &claims)
		if err != nil {
			mErr.Append(err)
			continue
		}
		enc = append(enc, jse)
	}
	if len(mErr) != 0 {
		panic("error generating tokens")
	}
	return sig, enc
}
