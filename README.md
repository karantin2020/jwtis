## JWTIS - JWT issuer server

Stand alone JWT issuer server. Just creates and renews JSON Web Tokens.

Used `gopkg.in/square/go-jose.v2` library.  
**NOT** github.com/dgrijalva/jwt-go.  
But produced JSON Web Tokens are standard and may be verified and decrypted with any other library.  
Client server (app) may use `github.com/dgrijalva/jwt-go` to verify tokens.

#### Installation

To install JWTIS, you need to install Go and set your Go workspace first.

1. Download and install it:

```sh
$ go get -u -d github.com/karantin2020/jwtis/cmd
$ go install -o jwtis github.com/karantin2020/jwtis/cmd
```

2. Import as library:

```go
import "github.com/karantin2020/jwtis"
```

#### Server configuration

```sh
./jwtis -h

Usage: jwtis [OPTIONS]

JWT issuer server. Provides trusted JWT tokens

Source https://github.com/karantin2020/jwtis

Options:
  -V, --version      Show the version and exit
  -l, --listen       ip:port to listen to (env $JWTIS_ADDRESS) (default "127.0.0.1:4343")
      --tls          Use tls connection [not implemented yet] (env $JWTIS_TLS)
      --sigAlg       Default algorithn to be used for sign. Possible values are: ES256 ES384 ES512 EdDSA RS256 RS384 RS512 PS256 PS384 PS512 (env $JWTIS_SIG_ALG) (default "RS256")
      --sigBits      Default key size in bits for sign key (env $JWTIS_SIG_BITS) (default 2048)
      --encAlg       Default algorithn to be used for encrypt. Possible values are RSA1_5 RSA-OAEP RSA-OAEP-256 ECDH-ES ECDH-ES+A128KW ECDH-ES+A192KW ECDH-ES+A256KW (env $JWTIS_ENC_ALG) (default "ECDH-ES+A256KW")
      --encBits      Default key size in bits for encrypt (env $JWTIS_ENC_BITS) (default 521)
  -e, --expiry       Default keys time to live, expiration time [Duration string] (env $JWTIS_EXPIRY) (default "4320h")
  -a, --authTTL      Default auth JWT token time to live, expiration time [Duration string] (env $JWTIS_AUTH_TTL) (default "72h")
  -r, --refreshTTL   Default refresh JWT token time to live, expiration time [Duration string] (env $JWTIS_REFRESH_TTL) (default "720h")
  -n, --name         Name of this service (env $JWTIS_NAME) (default "JWTIS")
  -p, --pswd         Storage password. App generates password with db creation. Later user must provide a password to access the database (env $JWTIS_PSWD)
  -d, --dbPath       Path to store keys db (env $JWTIS_DB_PATH) (default "./data/keys.db")
  -v, --verbose      Verbose. Show detailed logs (env $JWTIS_VERBOSE)
```

#### Start server

```sh
./jwtis
Welcome. Started jwtis version v0.0.1
Created new bbolt database to store app's data
Generated new password: '8jf*4FrKZBwhJ&]A!W0G!3~79jP$K2Wz'
Please save the password safely, it's not recoverable
Current configuration:
  internalRepo.configs.listen:          127.0.0.1:4343
  internalRepo.configs.tls:             false
  internalRepo.configs.sigAlg:          RS256
  internalRepo.configs.sigBits:         2048
  internalRepo.configs.encAlg:          ECDH-ES+A256KW
  internalRepo.configs.encBits:         521
  internalRepo.configs.selfName:        JWTIS
  internalRepo.configs.expiry:          4320h0m0s
  internalRepo.configs.authTTL:         72h0m0s
  internalRepo.configs.refreshTTL:      720h0m0s
  confRepo.options.dbPath:              ./data/keys.db
jwtis works well
jwtis finished work

./jwtis -p '8jf*4FrKZBwhJ&]A!W0G!3~79jP$K2Wz'
Welcome. Started jwtis version v0.0.1
Found existing bbolt database storing app's data
Use user inserted password to bboltDB
Current configuration:
  internalRepo.configs.listen:          127.0.0.1:4343
  internalRepo.configs.tls:             false
  internalRepo.configs.sigAlg:          RS256
  internalRepo.configs.sigBits:         2048
  internalRepo.configs.encAlg:          ECDH-ES+A256KW
  internalRepo.configs.encBits:         521
  internalRepo.configs.selfName:        JWTIS
  internalRepo.configs.expiry:          4320h0m0s
  internalRepo.configs.authTTL:         72h0m0s
  internalRepo.configs.refreshTTL:      720h0m0s
  confRepo.options.dbPath:              ./data/keys.db
```

#### When started first time JWTIS will:

- generate new boltdb password
  - You must save this password, it's not recoverable
- create boltdb database file
- start server with default or user provided configuration

#### Terms

- jwtis - is this server
- client server (or app, business logic layer, domain logic layer) - the server which requests tokens from jwtis
- web client (user) - the end consumer, client, user which requests client server
- auth token and refresh token are described later in README

#### What is it for:

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

```
  ES256 ES384 ES512 EdDSA RS256 RS384 RS512 PS256 PS384 PS512
```

#### Encrypt algorithms

```
  RSA1_5 RSA-OAEP RSA-OAEP-256 ECDH-ES ECDH-ES+A128KW ECDH-ES+A192KW ECDH-ES+A256KW
```

#### JWTIS http endpoints

- /register/:kid
  `- register new client server (app)`

  - method

  ```
      POST
  ```

  - payload

  ```go
    type RegisterClientRequest struct {
        Expiry Duration `json:"expiry,omitempty"` // keys ttl, optional

        SigAlg  string `json:"sig_alg,omitempty"`  // default algorithn to be used for sign, optional
        SigBits int    `json:"sig_bits,omitempty"` // default key size in bits for sign, optional
        EncAlg  string `json:"enc_alg,omitempty"`  // default algorithn to be used for encrypt, optional
        EncBits int    `json:"enc_bits,omitempty"` // default key size in bits for encrypt, optional

        AuthTTL    Duration `json:"auth_ttl,omitempty"`    // default auth jwt ttl, optional
        RefreshTTL Duration `json:"refresh_ttl,omitempty"` // default refresh jwt ttl, optional
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

- /keys
  `- fetch client server (app) public keys [TODO]`

  - request for previously generated public keys for JWT
  - request for new pub and priv JSONWebKey, not for jwt issuing
  - and other functions
  - requests send parameters in url queue or req body

- /renew_keys
  `- request new client server (app) keys [TODO]`

  - method

- /issue_token
  `- request new token set for client server with kid`

  - method

  ```
  POST
  ```

  - payload

  ```go
  // NewTokenRequest sent to jwtis to fetch new jwt
  // ClientToken {string} - must be in header
  type NewTokenRequest struct {
    Kid                   string                 `json:"kid"` // Keys id to use
    AuthTokenValidTime    time.Duration          `json:"auth_token_valid_time,omitempty"`
    ResreshTokenValidTime time.Duration          `json:"resresh_token_valid_time,omitempty"`
    Claims                map[string]interface{} `json:"claims,omitempty"` // Custom claims
  }
  ```

  - response

  ```go
  // TokenResponse sent to client that requested tokens
  type TokenResponse struct {
    ID           string          `json:"id"`
    AuthToken    string          `json:"auth_token"`    // Short lived auth token
    RefreshToken string          `json:"refresh_token"` // Long lived refresh token
    Expiry       jwt.NumericDate `json:"expiry"`
  }
  ```

* /renew_token
  `- renew auth token for client server based on refresh token.`
  `Only if refresh token is valid. Otherwise need to request new token`

  - method

  ```
  POST
  ```

  - payload

  ```go
  // RenewTokenRequest sent to jwtis to fetch new jwt
  // ClientToken {string} - must be in header
  type RenewTokenRequest struct {
    Kid          string `json:"kid"` // Keys id to use
    RefreshToken string `json:"refresh_token"`
  }
  ```

  - response

  ```go
  // TokenResponse sent to client that requested tokens
  type TokenResponse struct {
    ID           string          `json:"id"`
    AuthToken    string          `json:"auth_token"`    // Short lived auth token
    RefreshToken string          `json:"refresh_token"` // Long lived refresh token
    Expiry       jwt.NumericDate `json:"expiry"`
  }
  ```

Contributions are welcome

#### For note: JWT Structure

1. "iss" (Issuer) Claim

   The "iss" (issuer) claim identifies the principal that issued the
   JWT. The processing of this claim is generally application specific.
   The "iss" value is a case-sensitive string containing a StringOrURI
   value. Use of this claim is OPTIONAL.

2. "sub" (Subject) Claim

   The "sub" (subject) claim identifies the principal that is the
   subject of the JWT. The claims in a JWT are normally statements
   about the subject. The subject value MUST either be scoped to be
   locally unique in the context of the issuer or be globally unique.
   The processing of this claim is generally application specific. The
   "sub" value is a case-sensitive string containing a StringOrURI
   value. Use of this claim is OPTIONAL.

3. "aud" (Audience) Claim

   The "aud" (audience) claim identifies the recipients that the JWT is
   intended for. Each principal intended to process the JWT MUST
   identify itself with a value in the audience claim. If the principal
   processing the claim does not identify itself with a value in the
   "aud" claim when this claim is present, then the JWT MUST be
   rejected. In the general case, the "aud" value is an array of case-
   sensitive strings, each containing a StringOrURI value. In the
   special case when the JWT has one audience, the "aud" value MAY be a
   single case-sensitive string containing a StringOrURI value. The
   interpretation of audience values is generally application specific.
   Use of this claim is OPTIONAL.

4. "exp" (Expiration Time) Claim

   The "exp" (expiration time) claim identifies the expiration time on
   or after which the JWT MUST NOT be accepted for processing. The
   processing of the "exp" claim requires that the current date/time
   MUST be before the expiration date/time listed in the "exp" claim.
   Implementers MAY provide for some small leeway, usually no more than
   a few minutes, to account for clock skew. Its value MUST be a number
   containing a NumericDate value. Use of this claim is OPTIONAL.

5. "nbf" (Not Before) Claim

   The "nbf" (not before) claim identifies the time before which the JWT
   MUST NOT be accepted for processing. The processing of the "nbf"
   claim requires that the current date/time MUST be after or equal to
   the not-before date/time listed in the "nbf" claim. Implementers MAY
   provide for some small leeway, usually no more than a few minutes, to
   account for clock skew. Its value MUST be a number containing a
   NumericDate value. Use of this claim is OPTIONAL.

6. "iat" (Issued At) Claim

   The "iat" (issued at) claim identifies the time at which the JWT was
   issued. This claim can be used to determine the age of the JWT. Its
   value MUST be a number containing a NumericDate value. Use of this
   claim is OPTIONAL.

7. "jti" (JWT ID) Claim

   The "jti" (JWT ID) claim provides a unique identifier for the JWT.
   The identifier value MUST be assigned in a manner that ensures that
   there is a negligible probability that the same value will be
   accidentally assigned to a different data object; if the application
   uses multiple issuers, collisions MUST be prevented among values
   produced by different issuers as well. The "jti" claim can be used
   to prevent the JWT from being replayed. The "jti" value is a case-
   sensitive string. Use of this claim is OPTIONAL.

Source is https://tools.ietf.org/html/rfc7519#section-4.1
