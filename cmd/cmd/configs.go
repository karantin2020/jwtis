package cmd

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/abronan/valkeyrie/store"
	"github.com/karantin2020/jwtis"
	jose "gopkg.in/square/go-jose.v2"
)

const (
	boltDBConfig = "boltdb:./data/jwtis.db" // default db config string
)

// TLSConfig config
type TLSConfig struct {
	CertFile   *string `json:"CertFile" yaml:"CertFile"`
	KeyFile    *string `json:"KeyFile" yaml:"KeyFile"`
	CACertFile *string `json:"CACertFile" yaml:"CACertFile"`
}

// HTTPConf config
type HTTPConf struct {
	Listen    *string `json:"Listen" yaml:"Listen"` // ip:port to listen to
	TLS       *bool   `json:"TLS" yaml:"TLS"`       // Future feature
	TLSConfig `json:"TLSConfig" yaml:"TLSConfig"`
}

// GrpcConf config
type GrpcConf struct {
	ListenGrpc *string `json:"ListenGrpc" yaml:"ListenGrpc"`
}

// Sign holds default keys generation options
type Sign struct {
	SigAlg  *string `json:"SigAlg" yaml:"SigAlg"`   // Default algorithm to be used for sign
	SigBits *int    `json:"SigBits" yaml:"SigBits"` // Default key size in bits for sign
}

// Encryption config
type Encryption struct {
	EncAlg  *string `json:"EncAlg" yaml:"EncAlg"`   // Default algorithm to be used for encrypt
	EncBits *int    `json:"EncBits" yaml:"EncBits"` // Default key size in bits for encrypt
	ContEnc *string `json:"ContEnc" yaml:"ContEnc"` // Default Content Encryption
}

// JwtTTL config
type JwtTTL struct {
	AuthTTL    *string `json:"AuthTTL" yaml:"AuthTTL"`       // Default value for auth jwt ttl
	RefreshTTL *string `json:"RefreshTTL" yaml:"RefreshTTL"` // Default value for refresh jwt ttl
}

// KeyGeneration config
type KeyGeneration struct {
	// keys generation options
	Sign       `json:"Sign" yaml:"Sign"`
	Encryption `json:"Encryption" yaml:"Encryption"`
	Expiry     *string `json:"Expiry" yaml:"Expiry"`
	JwtTTL     `json:"JwtTTL" yaml:"JwtTTL"`
}

type setByUser struct {
	listenSetByUser     bool
	listenGrpcSetByUser bool
	tlsSetByUser        bool
	certFileSetByUser   bool
	keyFileSetByUser    bool
	caCertFileSetByUser bool
	sigAlgSetByUser     bool
	sigBitsSetByUser    bool
	encAlgSetByUser     bool
	encBitsSetByUser    bool
	contEncSetByUser    bool
	expirySetByUser     bool
	authTTLSetByUser    bool
	refreshTTLSetByUser bool
	selfNameSetByUser   bool
	passwordSetByUser   bool
	dbConfigSetByUser   bool
	configFileSetByUser bool
	logPathSetByUser    bool
	verboseSetByUser    bool
}

type defaults struct {
	defListen     string
	defListenGrpc string
	defTLS        bool
	defCertFile   string
	defKeyFile    string
	defCACertFile string
	defSigAlg     string
	defSigBits    int
	defEncAlg     string
	defEncBits    int
	defContEnc    string
	defExpiry     string
	defAuthTTL    string
	defRefreshTTL string
	defSelfName   string
	defPassword   string
	defDBConfig   string
	defConfigFile string
	defLogPath    string
	defVerbose    bool
}

// Options config
type Options struct {
	HTTPConf      `json:"HTTPConf" yaml:"HTTPConf"`
	GrpcConf      `json:"GrpcConf" yaml:"GrpcConf"`
	KeyGeneration `json:"KeyGeneration" yaml:"KeyGeneration"`
	SelfName      *string `json:"SelfName" yaml:"SelfName"` // Name of this service

	// internal options
	password *string `yaml:"-"` // Storage password. App generates password with db creation.
	// Later user must provide a password to access the database
	LogPath    *string `json:"LogPath" yaml:"LogPath"`
	DBConfig   *string `json:"DBConfig" yaml:"DBConfig"`
	ConfigFile *string `json:"ConfigFile" yaml:"ConfigFile"`
	Verbose    *bool   `json:"Verbose" yaml:"Verbose"`
	setByUser  `yaml:"-"`
}

// StoreClientTLSConfig config
type StoreClientTLSConfig struct {
	CertFile           string `json:"CertFile" yaml:"CertFile"`
	KeyFile            string `json:"KeyFile" yaml:"KeyFile"`
	CACertFile         string `json:"CACertFile" yaml:"CACertFile"`
	InsecureSkipVerify bool   `json:"InsecureSkipVerify" yaml:"InsecureSkipVerify"`
}

// StoreConfig config
type StoreConfig struct {
	ClientTLS *StoreClientTLSConfig `json:"ClientTLS" yaml:"ClientTLS"`
	// ConnectionTimeout is time.Duration in string format
	ConnectionTimeout string `json:"ConnectionTimeout" yaml:"ConnectionTimeout"`
	// SyncPeriod is time.Duration in string format
	SyncPeriod string `json:"SyncPeriod" yaml:"SyncPeriod"`
	// Bucket            string `json:"Bucket" yaml:"Bucket"`
	PersistConnection bool   `json:"PersistConnection" yaml:"PersistConnection"`
	Username          string `json:"Username" yaml:"Username"`
	Password          string `json:"Password" yaml:"Password"`
	Token             string `json:"Token" yaml:"Token"`
}

// Config contains app option values
type Config struct {
	defaults    `yaml:"-"`
	Options     `json:"Options" yaml:"Options"`
	StoreConfig *StoreConfig `json:"StoreConfig" yaml:"StoreConfig"`
	// bucketName holds app bucket name
	// to store configs and keys
	bucketName string `yaml:"-"`
}

// NewConfig returns initiated config instance
func NewConfig(bucketName string) *Config {
	p := &Config{
		defaults: defaults{
			defListen:     "127.0.0.1:4343",
			defListenGrpc: "127.0.0.1:40430",
			defTLS:        false,
			defCertFile:   "",
			defKeyFile:    "",
			defCACertFile: "",
			defSigAlg:     "ES256",
			defSigBits:    256,
			defEncAlg:     "ECDH-ES+A256KW",
			defEncBits:    256,
			defContEnc:    "A256GCM",
			defExpiry:     "4320h",
			defAuthTTL:    "72h",
			defRefreshTTL: "720h",
			defSelfName:   "JWTIS",
			defPassword:   "",
			defDBConfig:   boltDBConfig,
			defConfigFile: "./data/config.json",
			defLogPath:    "./data/jwtis.log",
			defVerbose:    false,
		},
		bucketName: bucketName,
		StoreConfig: &StoreConfig{
			ConnectionTimeout: "30s",
			SyncPeriod:        "0s",
			// Bucket:            bucketName,
			PersistConnection: true,
		},
	}
	return p
}

// GetStoreConfig converts internal config to *store.Config
func (c Config) GetStoreConfig() (*store.Config, error) {
	cs := c.StoreConfig
	if cs == nil {
		return nil, fmt.Errorf("error convert to *store.Config: internal StoreConfig is nil pointer")
	}
	conf := &store.Config{
		ClientTLS:         &store.ClientTLSConfig{},
		Bucket:            c.bucketName,
		PersistConnection: cs.PersistConnection,
		Username:          cs.Username,
		Password:          cs.Password,
		Token:             cs.Token,
	}
	if cs.ClientTLS != nil {
		conf.ClientTLS = &store.ClientTLSConfig{
			CertFile:   cs.ClientTLS.CertFile,
			KeyFile:    cs.ClientTLS.KeyFile,
			CACertFile: cs.ClientTLS.CACertFile,
		}
		conf.TLS = &tls.Config{
			InsecureSkipVerify: cs.ClientTLS.InsecureSkipVerify,
		}
	}
	var err error
	conf.ConnectionTimeout, err = time.ParseDuration(cs.ConnectionTimeout)
	if err != nil {
		return nil, fmt.Errorf("error convert to *store.Config, wrong ConnectionTimeout format: %s",
			err.Error())
	}
	conf.SyncPeriod, err = time.ParseDuration(cs.SyncPeriod)
	if err != nil {
		return nil, fmt.Errorf("error convert to *store.Config, wrong SyncPeriod format: %s",
			err.Error())
	}
	return conf, nil
}

func (c Config) getKeysRepoOptions() (*jwtis.DefaultOptions, error) {
	opts := jwtis.DefaultOptions{
		SigAlg:  *c.SigAlg,
		SigBits: *c.SigBits,
		EncAlg:  *c.EncAlg,
		EncBits: *c.EncBits,
	}
	var err error
	opts.Expiry, err = time.ParseDuration(*c.Expiry)
	if err != nil {
		return nil, fmt.Errorf("error parsing config Expiry value: %s", err.Error())
	}
	opts.AuthTTL, err = time.ParseDuration(*c.AuthTTL)
	if err != nil {
		return nil, fmt.Errorf("error parsing config AuthTTL value: %s", err.Error())
	}
	opts.RefreshTTL, err = time.ParseDuration(*c.RefreshTTL)
	if err != nil {
		return nil, fmt.Errorf("error parsing config RefreshTTL value: %s", err.Error())
	}
	return &opts, nil
}

func (c *Config) defToNil() {
	if c == nil {
		return
	}
	if !c.listenSetByUser {
		c.Listen = nil
	}
	if !c.listenGrpcSetByUser {
		c.ListenGrpc = nil
	}
	if !c.tlsSetByUser {
		c.TLS = nil
	}
	if !c.certFileSetByUser {
		c.CertFile = nil
	}
	if !c.keyFileSetByUser {
		c.KeyFile = nil
	}
	if !c.caCertFileSetByUser {
		c.CACertFile = nil
	}
	if !c.sigAlgSetByUser {
		c.SigAlg = nil
	}
	if !c.sigBitsSetByUser {
		c.SigBits = nil
	}
	if !c.encAlgSetByUser {
		c.EncAlg = nil
	}
	if !c.encBitsSetByUser {
		c.EncBits = nil
	}
	if !c.contEncSetByUser {
		c.ContEnc = nil
	}
	if !c.expirySetByUser {
		c.Expiry = nil
	}
	if !c.authTTLSetByUser {
		c.AuthTTL = nil
	}
	if !c.refreshTTLSetByUser {
		c.RefreshTTL = nil
	}
	if !c.selfNameSetByUser {
		c.SelfName = nil
	}
	if !c.passwordSetByUser {
		c.password = nil
	}
	if !c.dbConfigSetByUser {
		c.DBConfig = nil
	}
	if !c.configFileSetByUser {
		c.ConfigFile = nil
	}
	if !c.logPathSetByUser {
		c.LogPath = nil
	}
	if !c.verboseSetByUser {
		c.Verbose = nil
	}
}

// Exclude the next config from merge:
//  - password (just cmd or env source but not from file. Nothing to merge)
//  - ConfigFile (the same reason)
func mergeConfig(dst, src *Config) error {
	if dst == nil {
		return fmt.Errorf("mergeConfig: destination Config pointer is nil")
	}
	if src == nil {
		return fmt.Errorf("mergeConfig: source Config pointer is nil")
	}
	if src.Listen != nil {
		dst.Listen = src.Listen
	}
	if src.ListenGrpc != nil {
		dst.ListenGrpc = src.ListenGrpc
	}
	if src.TLS != nil {
		dst.TLS = src.TLS
	}
	if src.CertFile != nil {
		dst.CertFile = src.CertFile
	}
	if src.KeyFile != nil {
		dst.KeyFile = src.KeyFile
	}
	if src.CACertFile != nil {
		dst.CACertFile = src.CACertFile
	}
	if src.SigAlg != nil {
		dst.SigAlg = src.SigAlg
	}
	if src.SigBits != nil {
		dst.SigBits = src.SigBits
	}
	if src.EncAlg != nil {
		dst.EncAlg = src.EncAlg
	}
	if src.EncBits != nil {
		dst.EncBits = src.EncBits
	}
	if src.ContEnc != nil {
		dst.ContEnc = src.ContEnc
	}
	if src.Expiry != nil {
		dst.Expiry = src.Expiry
	}
	if src.AuthTTL != nil {
		dst.AuthTTL = src.AuthTTL
	}
	if src.RefreshTTL != nil {
		dst.RefreshTTL = src.RefreshTTL
	}
	if src.SelfName != nil {
		dst.SelfName = src.SelfName
	}
	if src.DBConfig != nil {
		dst.DBConfig = src.DBConfig
	}
	if src.LogPath != nil {
		dst.LogPath = src.LogPath
	}
	if src.Verbose != nil {
		dst.Verbose = src.Verbose
	}

	if src.StoreConfig == nil {
		return nil
	}
	if dst.StoreConfig == nil {
		dst.StoreConfig = &StoreConfig{}
	}

	// merge StoreConfig
	if src.StoreConfig.ConnectionTimeout != "" {
		dst.StoreConfig.ConnectionTimeout = src.StoreConfig.ConnectionTimeout
	}
	// if src.StoreConfig.Bucket != "" {
	// 	dst.StoreConfig.Bucket = src.StoreConfig.Bucket
	// }
	if src.StoreConfig.PersistConnection != false {
		dst.StoreConfig.PersistConnection = src.StoreConfig.PersistConnection
	}
	if src.StoreConfig.ClientTLS != nil {
		if dst.StoreConfig.ClientTLS == nil {
			dst.StoreConfig.ClientTLS = &StoreClientTLSConfig{}
		}
		if src.StoreConfig.ClientTLS.CertFile != "" {
			dst.StoreConfig.ClientTLS.CertFile = src.StoreConfig.ClientTLS.CertFile
		}
		if src.StoreConfig.ClientTLS.KeyFile != "" {
			dst.StoreConfig.ClientTLS.KeyFile = src.StoreConfig.ClientTLS.KeyFile
		}
		if src.StoreConfig.ClientTLS.CACertFile != "" {
			dst.StoreConfig.ClientTLS.CACertFile = src.StoreConfig.ClientTLS.CACertFile
		}
	}
	if src.StoreConfig.SyncPeriod != "" {
		dst.StoreConfig.SyncPeriod = src.StoreConfig.SyncPeriod
	}
	if src.StoreConfig.Username != "" {
		dst.StoreConfig.Username = src.StoreConfig.Username
	}
	if src.StoreConfig.Password != "" {
		dst.StoreConfig.Password = src.StoreConfig.Password
	}
	if src.StoreConfig.Token != "" {
		dst.StoreConfig.Token = src.StoreConfig.Token
	}

	return nil
}

func (c Config) printConfigs() {
	fmt.Printf("Current configuration:\n")
	fmt.Printf("  configs.listen:\t%s\n", *c.Listen)
	fmt.Printf("  configs.listenGrpc:\t%s\n", *c.ListenGrpc)
	fmt.Printf("  configs.tls:\t\t%t\n", *c.TLS)
	fmt.Printf("  configs.sigAlg:\t%s\n", *c.SigAlg)
	fmt.Printf("  configs.sigBits:\t%d\n", *c.SigBits)
	fmt.Printf("  configs.encAlg:\t%s\n", *c.EncAlg)
	fmt.Printf("  configs.encBits:\t%d\n", *c.EncBits)
	fmt.Printf("  configs.contEnc:\t%s\n", *c.ContEnc)
	fmt.Printf("  configs.selfName:\t%s\n", string(*c.SelfName))
	fmt.Printf("  configs.expiry:\t%s\n", *c.Expiry)
	fmt.Printf("  configs.authTTL:\t%s\n", *c.AuthTTL)
	fmt.Printf("  configs.refreshTTL:\t%s\n", *c.RefreshTTL)
	// fmt.Printf("internalRepo.configs.password: '%s'\n", string(p.password))
	fmt.Printf("  configs.DBConfig:\t%s\n", *c.DBConfig)
}

func (c Config) validate() error {
	var mErr jwtis.Error

	switch *c.SigAlg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		if *c.SigBits != 0 && *c.SigBits < 2048 {
			mErr.Append(f(errInvalidSigBitsValue, *c.SigAlg, *c.SigBits))
		}
	case "ES256", "ES384", "ES512", "EdDSA":
		keylen := map[string]int{
			"ES256": 256,
			"ES384": 384,
			"ES512": 521,
			"EdDSA": 256,
		}
		if *c.SigBits != 0 && *c.SigBits != keylen[*c.SigAlg] {
			mErr.Append(f(errInvalidSigBitsValueA, *c.SigAlg, *c.SigBits))
		}
	default:
		mErr.Append(errInvalidSigConfig)
	}

	switch *c.EncAlg {
	case "RSA1_5", "RSA-OAEP", "RSA-OAEP-256":
		if *c.EncBits != 0 && *c.EncBits < 2048 {
			mErr.Append(f(errInvalidEncBitsValue, *c.EncAlg, *c.EncBits))
		}
	case "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW":
		if !containsInt(bits, *c.EncBits) {
			mErr.Append(f(errInvalidEncBitsValueA, *c.EncAlg, *c.EncBits))
		}
	default:
		mErr.Append(errInvalidEncConfig)
	}

	switch jose.ContentEncryption(*c.ContEnc) {
	case jose.A128GCM, jose.A192GCM, jose.A256GCM:
	default:
		mErr.Append(errInvalidContEnc)

	}

	expiry, err := time.ParseDuration(*c.Expiry)
	if err != nil {
		mErr.Append(f("error parsing config Expiry value: %s", err.Error()))
	}
	authTTL, err := time.ParseDuration(*c.AuthTTL)
	if err != nil {
		mErr.Append(f("error parsing config AuthTTL value: %s", err.Error()))
	}
	refreshTTL, err := time.ParseDuration(*c.RefreshTTL)
	if err != nil {
		mErr.Append(f("error parsing config RefreshTTL value: %s", err.Error()))
	}
	if int64(expiry) <= int64(refreshTTL) {
		mErr.Append(f("invalid expiry value: must be more than refreshTTL"))
	}
	if int64(refreshTTL) <= int64(authTTL) {
		mErr.Append(f("invalid refreshTTL and authTTL values: authTTL must be less than refreshTTL"))
	}

	if len(mErr) != 0 {
		return mErr
	}
	return nil
}

var (
	bits = []int{0, 256, 384, 521}
)

var (
	f = fmt.Errorf

	errInvalidEncBitsValue  = "%s: too short enc key for RSA `alg`, 2048+ is required, have: %d"
	errInvalidEncBitsValueA = "%s: this enc elliptic curve supports bit length one of 256, 384, 521, have: %d"
	errInvalidEncConfig     = fmt.Errorf("invalid encrypt config flags")
	errInvalidSigBitsValue  = "%s: too short sig key for RSA `alg`, 2048+ is required, have: %d"
	errInvalidSigBitsValueA = "%s: this sig elliptic curve supports bit length one of 256, 384, 521, have: %d, you just can set it to 0"
	errInvalidSigConfig     = fmt.Errorf("invalid sign config flags")
	errInvalidContEnc       = fmt.Errorf("invalid content encryption value")
)

func containsString(l []string, s string) bool {
	for i := range l {
		if l[i] == s {
			return true
		}
	}
	return false
}

func containsInt(l []int, s int) bool {
	for i := range l {
		if l[i] == s {
			return true
		}
	}
	return false
}
