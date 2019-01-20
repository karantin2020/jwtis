package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"

	resty "gopkg.in/resty.v1"

	"github.com/karantin2020/jwtis"
	jwthttp "github.com/karantin2020/jwtis/http"
	jose "gopkg.in/square/go-jose.v2"
)

var (
	// ErrClientRegistered error if client is registered when try to register itz
	ErrClientRegistered = fmt.Errorf("client exists, cann't register again")
)

// Client is jwtis client type
type Client struct {
	cfg Config
	*resty.Client
}

// Config is a set of configs for Client
type Config struct {
	// ID is ublic id of the client used to identify it's key id on JWTIS
	ID string

	// PublicSigKey is public sign key
	PublicSigKey jose.JSONWebKey

	// PublicEncKey is public encryption key
	PublicEncKey jose.JSONWebKey

	// IssuerURL is the JWTIS endpoint
	IssuerURL string

	// Expires specifies how long client keys are valid for.
	Expires time.Duration

	// http endpoints
	paths
}

type paths struct {
	registerPath   string
	keysPath       string
	issueTokenPath string
	renewTokenPath string
}

const (
	registerPath   = "/register"
	keysPath       = "/keys"
	issueTokenPath = "/issue_token"
	renewTokenPath = "/renew_token"
)

// New returns pointer to new Client with provided configuration
func New(id, issuerURL string) *Client {
	issuerURL = strings.TrimSuffix(issuerURL, "/")
	clt := &Client{cfg: Config{
		ID:        id,
		IssuerURL: issuerURL,
	}}
	// Customize the Transport to have larger connection pool
	var defaultTransport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	clt.cfg.paths = endpoints(issuerURL, id)
	clt.Client = resty.New().SetTransport(defaultTransport) // &http.Client{Transport: defaultTransport}
	return clt
}

func endpoints(issuerURL, id string) paths {
	return paths{
		registerPath:   fmt.Sprintf("%s%s/%s", issuerURL, registerPath, id),
		keysPath:       fmt.Sprintf("%s%s/%s", issuerURL, keysPath, id),
		issueTokenPath: fmt.Sprintf("%s%s", issuerURL, issueTokenPath),
		renewTokenPath: fmt.Sprintf("%s%s", issuerURL, renewTokenPath),
	}
}

// Register registers new jwtis client with client id as kid
func (c *Client) Register(cltReq interface{}) error {
	if cltReq == nil {
		return fmt.Errorf("Register claims are nil pointer")
	}
	m, err := mapOrStruct(cltReq)
	if err != nil {
		return fmt.Errorf("error in Register claims: %s", err.Error())
	}
	resp, err := c.Client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(&m).
		SetResult(&jwthttp.RegisterClientResponse{}).
		SetError(&jwthttp.ErrorResponse{}).
		Post(c.cfg.registerPath)
	if err != nil {
		return fmt.Errorf("Got error: %v", err)
	}
	defer resp.RawResponse.Body.Close()
	if resp.StatusCode() == http.StatusForbidden {
		return ErrClientRegistered
	}
	if resp.StatusCode() != http.StatusCreated {
		return fmt.Errorf("error register new client: %v", resp.Error().(*jwthttp.ErrorResponse))
	}
	regResp := resp.Result().(*jwthttp.RegisterClientResponse)
	c.cfg.PublicEncKey = regResp.PubEncKey
	c.cfg.PublicSigKey = regResp.PubSigKey
	c.cfg.Expires = time.Duration(regResp.Expiry)
	return nil
}

// RegisterIfNotExist registers new jwtis client with client id as kid
// or pulls public keys if client is registered already
func (c *Client) RegisterIfNotExist(cltReq interface{}) error {
	var mErr jwtis.Error
	if rErr := c.Register(cltReq); rErr != nil {
		if rErr == ErrClientRegistered {
			if pErr := c.GetPubKeys(); pErr != nil {
				mErr.Append(pErr)
			}
			return nil
		}
		mErr.Append(rErr)
		return mErr
	}
	return nil
}

// GetPubKeys func
func (c *Client) GetPubKeys() error {
	resp, err := c.Client.R().
		SetHeader("Content-Type", "application/json").
		SetResult(&jwtis.SigEncKeys{}).
		SetError(&jwthttp.ErrorResponse{}).
		Get(c.cfg.keysPath)
	defer resp.RawResponse.Body.Close()
	if err != nil {
		return fmt.Errorf("Got error: %v", err)
	}
	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("error get public keys: %v", resp.Error().(*jwthttp.ErrorResponse))
	}
	keyResp := resp.Result().(*jwtis.SigEncKeys)
	c.cfg.PublicSigKey = *keyResp.Sig
	c.cfg.PublicEncKey = *keyResp.Enc
	return nil
}

// NewJWT rewuests new jwt token
func (c *Client) NewJWT(claims interface{}) (*jwthttp.TokenResponse, error) {
	m, err := mapOrStruct(claims)
	if err != nil {
		return nil, fmt.Errorf("error in NewJWT: %s", err.Error())
	}
	resp, err := c.Client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(&jwthttp.NewTokenRequest{
			Kid:    c.cfg.ID,
			Claims: m,
		}).
		SetResult(&jwthttp.TokenResponse{}). // or SetResult(AuthSuccess{}).
		SetError(&jwthttp.ErrorResponse{}).
		Post(c.cfg.issueTokenPath)
	defer resp.RawResponse.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("error in client NewJWT, error request: %s", err.Error())
	}
	if resp.StatusCode() != http.StatusCreated {
		return nil, fmt.Errorf("error get new JWT: %v", resp.Error().(*jwthttp.ErrorResponse))
	}
	tokResp := resp.Result().(*jwthttp.TokenResponse)
	return tokResp, nil
}

func mapOrStruct(i interface{}) (map[string]interface{}, error) {
	m, ok := i.(map[string]interface{})
	var err error
	switch {
	case ok:
	case reflect.Indirect(reflect.ValueOf(i)).Kind() == reflect.Struct:
		m, err = normalize(i)
		if err != nil {
			return nil, fmt.Errorf("error in map or struct: %s", err.Error())
		}
	default:
		return nil, fmt.Errorf("provided interface{} is not a struct or a map")
	}
	return m, nil
}

func normalize(i interface{}) (map[string]interface{}, error) {
	m := make(map[string]interface{})

	raw, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}

	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()

	if err := d.Decode(&m); err != nil {
		return nil, err
	}

	return m, nil
}
