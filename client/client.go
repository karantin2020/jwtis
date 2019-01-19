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

	// Expires optionally specifies how long the token is valid for.
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
func New(cfg Config) *Client {
	cfg.IssuerURL = strings.TrimSuffix(cfg.IssuerURL, "/")
	clt := &Client{cfg: cfg}
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
	clt.cfg.paths = endpoints(cfg.IssuerURL, cfg.ID)
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
	resp, err := c.Client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(cltReq).
		SetResult(&jwthttp.RegisterClientResponse{}). // or SetResult(AuthSuccess{}).
		Post(c.cfg.registerPath)
	defer resp.RawResponse.Body.Close()
	if err != nil {
		return fmt.Errorf("Got error: %v", err)
	}
	regResp := resp.Result().(*jwthttp.RegisterClientResponse)
	c.cfg.PublicEncKey = regResp.PubEncKey
	c.cfg.PublicSigKey = regResp.PubSigKey
	c.cfg.Expires = time.Duration(regResp.Expiry)
	return nil
}

// GetPubKeys func
func (c *Client) GetPubKeys() error {
	resp, err := c.Client.R().
		SetHeader("Content-Type", "application/json").
		SetResult(&jwtis.SigEncKeys{}). // or SetResult(AuthSuccess{}).
		Get(c.cfg.keysPath)
	defer resp.RawResponse.Body.Close()
	if err != nil {
		return fmt.Errorf("Got error: %v", err)
	}
	keyResp := resp.Result().(*jwtis.SigEncKeys)
	c.cfg.PublicSigKey = *keyResp.Sig
	c.cfg.PublicEncKey = *keyResp.Enc
	return nil
}

// NewJWT rewuests new jwt token
func (c *Client) NewJWT(claims interface{}) (*jwthttp.TokenResponse, error) {
	m, ok := claims.(map[string]interface{})
	var err error
	switch {
	case ok:
	case reflect.Indirect(reflect.ValueOf(claims)).Kind() == reflect.Struct:
		m, err = normalize(claims)
		if err != nil {
			return nil, fmt.Errorf("error in client NewJWT normalizing claims: %s", err.Error())
		}
	default:
		return nil, fmt.Errorf("error in client NewJWT, invalid claims: '%v'", claims)
	}
	resp, err := c.Client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(&jwthttp.NewTokenRequest{
			Kid:    c.cfg.ID,
			Claims: m,
		}).
		SetResult(&jwthttp.TokenResponse{}). // or SetResult(AuthSuccess{}).
		Post(c.cfg.issueTokenPath)
	defer resp.RawResponse.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("error in client NewJWT, error request: %s", err.Error())
	}
	tokResp := resp.Result().(*jwthttp.TokenResponse)
	return tokResp, nil
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
