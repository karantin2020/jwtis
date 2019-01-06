## JWTIS - JWT issuer server

Stand alone JWT issuer server. Just creates and renews JSON Web Tokens.

Used `gopkg.in/square/go-jose.v2` library.  
**NOT** github.com/dgrijalva/jwt-go.  
But produced JSON Web Tokens are standard and may be verified and decrypted with any other library.  
Client server (app) may use `github.com/dgrijalva/jwt-go` to verify tokens.

#### Terms

- jwtis - is this server
- client server (or app, business logic layer, domain logic layer) - the server which requests tokens from jwtis
- web client (user) - the end consumer, client, user which requests client server
- auth token and refresh token are described later in README

What is it for:

- automate sign and encrypt key creation, storing and revision
- automate producing JWTs (no need to implement it yourself)
- providing two tokens: short lived auth token and long lived refresh token
- signed and encrypted refresh token provides more security
- signed auth token may be verified with it's signature and with matching refresh token
- client server fetches tokens' set for certain web client (user) and authenticates user with that tokens
- client server (app) never encrypts anything
- many client servers may use one JWTIS instance
- all info on JWTIS is stored encrypted in embedded database

#### Short-lived (minutes) JWT Auth Token

The short-lived jwt auth token allows the user to make stateless requests to protected api endpoints. It has an expiration time of 15 minutes by default and will be refreshed by the longer-lived refresh token.

#### Longer-lived (hours/days) JWT Refresh Token

This longer-lived token will be used to update the auth tokens. These tokens have a 72 hour expiration time by default which will be updated each time an auth token is refreshed.  
Refresh tokens are signed and encrypted  
These refresh tokens can be revoked by an authorized client

#### JWTIS flow implementation

- client server (business logic layer, domain logic layer) requests JWT
- JWTIS generates tokens and sends them to client server
- client server authenticates web client with this tokens as ussually

#### Sign algorithms

```go
    sigAlgs = []string{
            string(jose.ES256), string(jose.ES384), string(jose.ES512),
            string(jose.EdDSA), string(jose.RS256), string(jose.RS384),
            string(jose.RS512), string(jose.PS256), string(jose.PS384),
            string(jose.PS512),
        }
```

#### Encrypt algorithms

```go
    encAlgs = []string{
    	string(jose.RSA1_5), string(jose.RSA_OAEP),
    	string(jose.RSA_OAEP_256), string(jose.ECDH_ES),
    	string(jose.ECDH_ES_A128KW), string(jose.ECDH_ES_A192KW),
    	string(jose.ECDH_ES_A256KW),
    }
```

#### JWTIS http endpoints

- /register
  `- register new client server (app)`

  - method

```
    POST
```

- payload

```go
  type RegisterClientRequest struct {
      Kid string `json:"kid"` // Keys id to use

      // Sign and encrypt keys config. If not provided then use default JWTIS values
      SigAlg  string `json:"sig_alg"`  // algorithn to be used for sign
      SigBits string `json:"sig_bits"` // key size in bits for sign
      EncAlg  string `json:"enc_alg"`  // algorithn to be used for encrypt
      EncBits string `json:"enc_bits"` // key size in bits for encrypt
  }
```

- response

```go
  type RegisterClientResponse struct {
      Kid         string          `json:"kid"`          // Keys id to use
      ClientToken string          `json:"client_token"` // Client token given after registration
      PubSigKey   jose.JSONWebKey `json:"pub_sig_key"`  // Public sign key to verify AuthTokens
      PubEncKey   jose.JSONWebKey `json:"pub_enc_key"`  // Public enc key to decrypt RefreshTokens
  }
```

- /issue_token
  `- request new token set for client server with kid`

  - method

  ```
    POST
  ```

  - payload

  ```go
    type NewTokenRequest struct {
        Kid                   string          `json:"kid"`          // Keys id to use
        ClientToken           string          `json:"client_token"` // Client token given after registration
        AuthTokenValidTime    jwt.NumericDate `json:"auth_token_valid_time"`
        ResreshTokenValidTime jwt.NumericDate `json:"resresh_token_valid_time"`
        Claims                interface{}     `json:"claims"` // Custom claims
    }
  ```

  - response

  ```go
  type NewTokenResponse struct {
        AuthToken    string `json:"auth_token"`    // Short lived auth token
        RefreshToken string `json:"refresh_token"` // Long lived refresh token
    }
  ```

- /renew_token
  `- renew auth token for client server based on refresh token.`
  `Only if refresh token is valid. Otherwise need to request new token`

  - method

  ```
    POST
  ```

  - payload

  ```go
    type RenewTokenRequest struct {
        Kid          string `json:"kid"`          // Keys id to use
        ClientToken  string `json:"client_token"` // Client token given after registration
        RefreshToken string `json:"refresh_token"`
    }
  ```

  - response

  ```go
  type NewTokenResponse struct {
        AuthToken    string `json:"auth_token"`    // Short lived auth token
        RefreshToken string `json:"refresh_token"` // Long lived refresh token
    }
  ```

Contributors are welcome

```

```
