package client

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/karantin2020/jwtis"
	jwtishttp "github.com/karantin2020/jwtis/http"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

func TestClient_ClientJWT(t *testing.T) {
	cl := New("test2", "http://127.0.0.1:4343")
	tests := []struct {
		name    string
		claims  interface{}
		wantErr bool
	}{
		{
			name:    "empty claims struct",
			claims:  struct{}{},
			wantErr: false,
		},
		{
			name:    "empty claims map",
			claims:  map[string]interface{}{},
			wantErr: false,
		},
		{
			name: "claims map with exp",
			claims: map[string]interface{}{
				"exp": 1548144343,
				"sub": "test_web_client",
				"aud": []string{"example.com", "ya.ru"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cl.NewJWT(tt.claims)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.NewJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			s, err := json.MarshalIndent(got, "", "  ")
			if err != nil {
				t.Errorf("error in client NewJWT, error marshal response: %s", err.Error())
			}
			fmt.Println(string(s))
		})
	}
}

func TestClient_GetPubKeys(t *testing.T) {
	cl := New("test2", "http://127.0.0.1:4343")
	t.Run("test positive", func(t *testing.T) {
		err := cl.GetPubKeys()
		if err != nil {
			t.Errorf("Client.GetPubKeys() error = %v", err)
			return
		}
		fmt.Printf("keys: \n%#v valid: %v\n%#v valid: %v\n",
			cl.cfg.PublicSigKey, cl.cfg.PublicSigKey.Valid(),
			cl.cfg.PublicEncKey, cl.cfg.PublicEncKey.Valid())
	})
}

func TestClient_ParsedJWT(t *testing.T) {
	cl := New("test2", "http://127.0.0.1:4343")
	err := cl.GetPubKeys()
	if err != nil {
		t.Errorf("Client.ParsedJWT() error = %v", err)
		return
	}
	t.Run("claims map with exp", func(t *testing.T) {
		// now := time.Now()
		now := NewNumericDate(time.Now())
		exp := NewNumericDate(now.Time().Add(3 * time.Hour))
		claims := Claims{
			Expiry:   NewNumericDate(time.Now().Add(3 * time.Hour)),
			IssuedAt: now,
			Subject:  "test_web_client",
			Audience: []string{"example.com", "ya.ru"},
		}
		got, err := cl.NewJWT(claims)
		if err != nil {
			t.Errorf("Client.ParsedJWT() error = %v", err)
			return
		}
		authClaims := Claims{}
		err = jwtis.ClaimsSigned(&cl.cfg.PublicSigKey, got.AccessToken, &authClaims)
		if err != nil {
			t.Errorf("Client.ParsedJWT() error = %v", err)
			return
		}
		s, err := json.MarshalIndent(authClaims, "", "  ")
		if err != nil {
			t.Errorf("error in client ParsedJWT, error marshal response: %s", err.Error())
		}
		fmt.Println(string(s))
		fmt.Printf("%+v\n", authClaims)
		if *exp != *authClaims.Expiry {
			t.Errorf("Client.ParsedJWT() error: invalid expiry, want=%v, got=%v", *exp, *authClaims.Expiry)
		}
		if *now != *authClaims.IssuedAt {
			t.Errorf("Client.ParsedJWT() error: invalid iat, want=%v, got=%v", *now, *authClaims.IssuedAt)
		}
	})
}

type Claims struct {
	Issuer    string       `json:"iss,omitempty"`
	Subject   string       `json:"sub,omitempty"`
	Audience  jwt.Audience `json:"aud,omitempty"`
	Expiry    *NumericDate `json:"exp,omitempty"`
	NotBefore *NumericDate `json:"nbf,omitempty"`
	IssuedAt  *NumericDate `json:"iat,omitempty"`
	ID        string       `json:"jti,omitempty"`
}

// NumericDate represents date and time as the number of seconds since the
// epoch, including leap seconds. Non-integer values can be represented
// in the serialized format, but we round to the nearest second.
type NumericDate int64

// NewNumericDate constructs NumericDate from time.Time value.
func NewNumericDate(t time.Time) *NumericDate {
	if t.IsZero() {
		return nil
	}

	// While RFC 7519 technically states that NumericDate values may be
	// non-integer values, we don't bother serializing timestamps in
	// claims with sub-second accurancy and just round to the nearest
	// second instead. Not convined sub-second accuracy is useful here.
	out := NumericDate(t.Unix())
	return &out
}

// MarshalJSON serializes the given NumericDate into its JSON representation.
func (n NumericDate) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(int64(n), 10)), nil
}

// Marshal serializes the given NumericDate into its JSON representation.
func (n NumericDate) Marshal() ([]byte, error) {
	return []byte(time.Unix(int64(n), 0).String()), nil
}

func (n NumericDate) String() string {
	return time.Unix(int64(n), 0).String()
}

// UnmarshalJSON reads a date from its JSON representation.
func (n *NumericDate) UnmarshalJSON(b []byte) error {
	s := string(b)

	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("error unmarshal")
	}

	*n = NumericDate(f)
	return nil
}

// Time returns time.Time representation of NumericDate.
func (n *NumericDate) Time() time.Time {
	if n == nil {
		return time.Time{}
	}
	return time.Unix(int64(*n), 0)
}

func Test_endpoints(t *testing.T) {
	type args struct {
		issuerURL string
		id        string
	}
	tests := []struct {
		name string
		args args
		want paths
	}{
		{
			name: "positive test",
			args: args{
				issuerURL: "http://127.0.0.1:4343",
				id:        "testid",
			},
			want: paths{
				registerPath:   "http://127.0.0.1:4343/register/testid",
				keysPath:       "http://127.0.0.1:4343/keys/testid",
				issueTokenPath: "http://127.0.0.1:4343/issue_token",
				renewTokenPath: "http://127.0.0.1:4343/renew_token",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := endpoints(tt.args.issuerURL, tt.args.id); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("endpoints() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_Register(t *testing.T) {
	type args struct {
		cltReq interface{}
	}
	tests := []struct {
		name    string
		cl      *Client
		args    args
		wantErr bool
	}{
		{
			name: "register negative",
			cl:   New("test3", "http://127.0.0.1:4343"),
			args: args{
				cltReq: jwtishttp.RegisterClientRequest{
					SigAlg:     "ES512",
					SigBits:    512,
					EncAlg:     "ECDH-ES+A256KW",
					EncBits:    256,
					AuthTTL:    jwtishttp.Duration(24 * time.Hour),
					RefreshTTL: jwtishttp.Duration(360 * time.Hour),
				},
			},
			wantErr: true,
		},
		{
			name: "register positive",
			cl:   New("test5", "http://127.0.0.1:4343"),
			args: args{
				cltReq: jwtishttp.RegisterClientRequest{
					SigAlg:     "ES512",
					SigBits:    521,
					EncAlg:     "ECDH-ES+A256KW",
					EncBits:    256,
					AuthTTL:    jwtishttp.Duration(24 * time.Hour),
					RefreshTTL: jwtishttp.Duration(360 * time.Hour),
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cl.Register(tt.args.cltReq); (err != nil) != tt.wantErr {
				t.Errorf("Client.Register() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			fmt.Printf("%#v\n", tt.cl.cfg)
		})
	}
}
