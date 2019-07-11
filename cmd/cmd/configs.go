package cmd

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/abronan/valkeyrie/store"
)

const (
	boltDBConfig = "boltdb:./data/jwtis.db" // default db config string
)

// TLSConfig config
type TLSConfig struct {
	CertFile   *string `json:"CertFile,omitempty" yaml:"CertFile,omitempty"`
	KeyFile    *string `json:"KeyFile,omitempty" yaml:"KeyFile,omitempty"`
	CACertFile *string `json:"CACertFile,omitempty" yaml:"CACertFile,omitempty"`
}

// HTTPConf config
type HTTPConf struct {
	Listen    *string `json:"Listen,omitempty" yaml:"Listen,omitempty"` // ip:port to listen to
	TLS       *bool   `json:"TLS,omitempty" yaml:"TLS,omitempty"`       // Future feature
	TLSConfig `json:"TLSConfig,omitempty" yaml:"TLSConfig,omitempty"`
}

// GrpcConf config
type GrpcConf struct {
	ListenGrpc *string `json:"ListenGrpc,omitempty" yaml:"ListenGrpc,omitempty"`
}

// Sign holds default keys generation options
type Sign struct {
	SigAlg  *string `json:"SigAlg,omitempty" yaml:"SigAlg,omitempty"`   // Default algorithm to be used for sign
	SigBits *int    `json:"SigBits,omitempty" yaml:"SigBits,omitempty"` // Default key size in bits for sign
}

// Encryption config
type Encryption struct {
	EncAlg  *string `json:"EncAlg,omitempty" yaml:"EncAlg,omitempty"`   // Default algorithm to be used for encrypt
	EncBits *int    `json:"EncBits,omitempty" yaml:"EncBits,omitempty"` // Default key size in bits for encrypt
	ContEnc *string `json:"ContEnc,omitempty" yaml:"ContEnc,omitempty"` // Default Content Encryption
}

// JwtTTL config
type JwtTTL struct {
	AuthTTL    *string `json:"AuthTTL,omitempty" yaml:"AuthTTL,omitempty"`       // Default value for auth jwt ttl
	RefreshTTL *string `json:"RefreshTTL,omitempty" yaml:"RefreshTTL,omitempty"` // Default value for refresh jwt ttl
}

// KeyGeneration config
type KeyGeneration struct {
	// keys generation options
	Sign       `json:"Sign,omitempty" yaml:"Sign,omitempty"`
	Encryption `json:"Encryption,omitempty" yaml:"Encryption,omitempty"`
	Expiry     *string `json:"Expiry,omitempty" yaml:"Expiry,omitempty"`
	JwtTTL     `json:"JwtTTL,omitempty" yaml:"JwtTTL,omitempty"`
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
	HTTPConf      `json:"HTTPConf,omitempty" yaml:"HTTPConf,omitempty"`
	GrpcConf      `json:"GrpcConf,omitempty" yaml:"GrpcConf,omitempty"`
	KeyGeneration `json:"KeyGeneration,omitempty" yaml:"KeyGeneration,omitempty"`
	SelfName      *string `json:"SelfName,omitempty" yaml:"SelfName,omitempty"` // Name of this service

	// internal options
	password *string `yaml:"-"` // Storage password. App generates password with db creation.
	// Later user must provide a password to access the database
	LogPath    *string `json:"LogPath,omitempty" yaml:"LogPath,omitempty"`
	DBConfig   *string `json:"DBConfig,omitempty" yaml:"DBConfig,omitempty"`
	ConfigFile *string `json:"ConfigFile,omitempty" yaml:"ConfigFile,omitempty"`
	Verbose    *bool   `json:"Verbose,omitempty" yaml:"Verbose,omitempty"`
	setByUser  `yaml:"-"`
}

// StoreClientTLSConfig config
type StoreClientTLSConfig struct {
	CertFile           string `json:"CertFile,omitempty" yaml:"CertFile,omitempty"`
	KeyFile            string `json:"KeyFile,omitempty" yaml:"KeyFile,omitempty"`
	CACertFile         string `json:"CACertFile,omitempty" yaml:"CACertFile,omitempty"`
	InsecureSkipVerify bool   `json:"InsecureSkipVerify,omitempty" yaml:"InsecureSkipVerify,omitempty"`
}

// StoreConfig config
type StoreConfig struct {
	ClientTLS *StoreClientTLSConfig `json:"ClientTLS,omitempty" yaml:"ClientTLS,omitempty"`
	// ConnectionTimeout is time.Duration in string format
	ConnectionTimeout string `json:"ConnectionTimeout,omitempty" yaml:"ConnectionTimeout,omitempty"`
	// SyncPeriod is time.Duration in string format
	SyncPeriod string `json:"SyncPeriod,omitempty" yaml:"SyncPeriod,omitempty"`
	// Bucket            string `json:"Bucket,omitempty" yaml:"Bucket,omitempty"`
	PersistConnection bool   `json:"PersistConnection,omitempty" yaml:"PersistConnection,omitempty"`
	Username          string `json:"Username,omitempty" yaml:"Username,omitempty"`
	Password          string `json:"Password,omitempty" yaml:"Password,omitempty"`
	Token             string `json:"Token,omitempty" yaml:"Token,omitempty"`
}

// Config contains app option values
type Config struct {
	defaults    `yaml:"-"`
	Options     `json:"Options,omitempty" yaml:"Options,omitempty"`
	StoreConfig *StoreConfig `json:"StoreConfig,omitempty" yaml:"StoreConfig,omitempty"`
	// BucketName holds configuration bucket name
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
func (c *Config) GetStoreConfig() (*store.Config, error) {
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
