package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	cli "github.com/jawher/mow.cli"
	"github.com/karantin2020/jwtis"
	"github.com/karantin2020/svalkey"
	"github.com/rs/zerolog"

	"github.com/abronan/valkeyrie"
	"github.com/abronan/valkeyrie/store"

	"github.com/abronan/valkeyrie/store/boltdb"
	"github.com/abronan/valkeyrie/store/consul"
	"github.com/abronan/valkeyrie/store/dynamodb"
	etcdv3 "github.com/abronan/valkeyrie/store/etcd/v3"
	"github.com/abronan/valkeyrie/store/redis"
	zk "github.com/abronan/valkeyrie/store/zookeeper"

	"encoding/json"
	// "gopkg.in/yaml.v2"
)

type rootCmd struct {
	config *Config
	// store    *svalkey.Store
	logger   zerolog.Logger
	keysRepo jwtis.KeysRepository
}

// SetGlobalOpts sets global cli options
func (r *rootCmd) SetGlobalOpts(app *cli.Cli, configBucket, envPrefix string) {
	app.Spec = "[-flgearnpdv] [--tls] [--certFile] [--keyFile] [--caCertFile]" +
		" [--sigAlg] [--sigBits] [--encAlg] [--encBits] [--contEnc] [--logPath]"
	confRepo := NewConfig(configBucket)
	confRepo.Listen = app.String(cli.StringOpt{
		Name:      "l listen",
		Value:     confRepo.defListen,
		Desc:      "http ip:port to listen to",
		EnvVar:    envPrefix + "HTTP_ADDRESS",
		SetByUser: &confRepo.listenSetByUser,
	})
	confRepo.ListenGrpc = app.String(cli.StringOpt{
		Name:      "g grpcAddr",
		Value:     confRepo.defListenGrpc,
		Desc:      "grpc ip:port to listen to",
		EnvVar:    envPrefix + "GRPC_ADDRESS",
		SetByUser: &confRepo.listenGrpcSetByUser,
	})
	confRepo.TLS = app.Bool(cli.BoolOpt{
		Name:      "tls",
		Value:     confRepo.defTLS,
		Desc:      "Use tls connection [not implemented yet]",
		EnvVar:    envPrefix + "TLS",
		SetByUser: &confRepo.tlsSetByUser,
	})

	confRepo.CertFile = app.String(cli.StringOpt{
		Name:      "certFile",
		Value:     confRepo.defCertFile,
		Desc:      "Default CertFile for tls",
		EnvVar:    envPrefix + "CERT_FILE",
		SetByUser: &confRepo.certFileSetByUser,
	})
	confRepo.KeyFile = app.String(cli.StringOpt{
		Name:      "keyFile",
		Value:     confRepo.defKeyFile,
		Desc:      "Default KeyFile for tls",
		EnvVar:    envPrefix + "KEY_FILE",
		SetByUser: &confRepo.keyFileSetByUser,
	})
	confRepo.CACertFile = app.String(cli.StringOpt{
		Name:      "caCertFile",
		Value:     confRepo.defCACertFile,
		Desc:      "Default CACertFile for tls",
		EnvVar:    envPrefix + "CA_CERT_FILE",
		SetByUser: &confRepo.caCertFileSetByUser,
	})

	confRepo.SigAlg = app.String(cli.StringOpt{
		Name:      "sigAlg",
		Value:     confRepo.defSigAlg,
		Desc:      "Default algorithm to be used for sign. Possible values are: ES256 ES384 ES512 EdDSA RS256 RS384 RS512 PS256 PS384 PS512",
		EnvVar:    envPrefix + "SIG_ALG",
		SetByUser: &confRepo.sigAlgSetByUser,
	})
	confRepo.SigBits = app.Int(cli.IntOpt{
		Name:      "sigBits",
		Value:     confRepo.defSigBits,
		Desc:      "Default key size in bits for sign key. Supported elliptic bit lengths are 256, 384, 521",
		EnvVar:    envPrefix + "SIG_BITS",
		SetByUser: &confRepo.sigBitsSetByUser,
	})
	confRepo.EncAlg = app.String(cli.StringOpt{
		Name:      "encAlg",
		Value:     confRepo.defEncAlg,
		Desc:      "Default algorithm to be used for encrypt. Possible values are RSA1_5 RSA-OAEP RSA-OAEP-256 ECDH-ES ECDH-ES+A128KW ECDH-ES+A192KW ECDH-ES+A256KW",
		EnvVar:    envPrefix + "ENC_ALG",
		SetByUser: &confRepo.encAlgSetByUser,
	})
	confRepo.EncBits = app.Int(cli.IntOpt{
		Name:      "encBits",
		Value:     confRepo.defEncBits,
		Desc:      "Default key size in bits for encrypt. Supported elliptic bit lengths are 256, 384, 521",
		EnvVar:    envPrefix + "ENC_BITS",
		SetByUser: &confRepo.encBitsSetByUser,
	})
	confRepo.ContEnc = app.String(cli.StringOpt{
		Name:      "contEnc",
		Value:     confRepo.defContEnc,
		Desc:      "Default content encryption. Possible values are A128GCM, A192GCM, A256GCM",
		EnvVar:    envPrefix + "CONT_ENC",
		SetByUser: &confRepo.contEncSetByUser,
	})
	confRepo.Expiry = app.String(cli.StringOpt{
		Name:      "e expiry",
		Value:     confRepo.defExpiry,
		Desc:      "Default keys time to live, expiration time [Duration string]",
		EnvVar:    envPrefix + "EXPIRY",
		SetByUser: &confRepo.expirySetByUser,
	})
	confRepo.AuthTTL = app.String(cli.StringOpt{
		Name:      "a authTTL",
		Value:     confRepo.defAuthTTL,
		Desc:      "Default auth JWT token time to live, expiration time [Duration string]",
		EnvVar:    envPrefix + "AUTH_TTL",
		SetByUser: &confRepo.authTTLSetByUser,
	})
	confRepo.RefreshTTL = app.String(cli.StringOpt{
		Name:      "r refreshTTL",
		Value:     confRepo.defRefreshTTL,
		Desc:      "Default refresh JWT token time to live, expiration time [Duration string]",
		EnvVar:    envPrefix + "REFRESH_TTL",
		SetByUser: &confRepo.refreshTTLSetByUser,
	})

	confRepo.SelfName = app.String(cli.StringOpt{
		Name:      "n name",
		Value:     confRepo.defSelfName,
		Desc:      "Name of this service",
		EnvVar:    envPrefix + "NAME",
		SetByUser: &confRepo.selfNameSetByUser,
	})
	confRepo.password = app.String(cli.StringOpt{
		Name:      "p pswd",
		Value:     confRepo.defPassword,
		Desc:      "Storage password. App generates password with db creation. Later user must provide a password to access the database",
		EnvVar:    envPrefix + "PSWD",
		SetByUser: &confRepo.passwordSetByUser,
	})
	confRepo.DBConfig = app.String(cli.StringOpt{
		Name:      "d dbConfig",
		Value:     confRepo.defDBConfig,
		Desc:      "Config to setup db",
		EnvVar:    envPrefix + "DB_CONFIG",
		SetByUser: &confRepo.dbConfigSetByUser,
	})
	confRepo.ConfigFile = app.String(cli.StringOpt{
		Name:      "f file",
		Value:     confRepo.defConfigFile,
		Desc:      "Path to config file",
		EnvVar:    envPrefix + "CONFIG_FILE",
		SetByUser: &confRepo.configFileSetByUser,
	})
	confRepo.LogPath = app.String(cli.StringOpt{
		Name:      "logPath",
		Value:     confRepo.defLogPath,
		Desc:      "Path to store logs",
		EnvVar:    envPrefix + "LOG_PATH",
		SetByUser: &confRepo.logPathSetByUser,
	})
	confRepo.Verbose = app.Bool(cli.BoolOpt{
		Name:      "v verbose",
		Value:     confRepo.defVerbose,
		Desc:      "Verbose. Show detailed logs",
		EnvVar:    envPrefix + "VERBOSE",
		SetByUser: &confRepo.verboseSetByUser,
	})
	r.config = confRepo
}

func (r *rootCmd) Logger() *zerolog.Logger {
	return &r.logger
}

func (r *rootCmd) before() {
	zerolog.SetGlobalLevel(zerolog.WarnLevel)
	if *r.config.Verbose {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
	// configs to merge
	var (
		// zeroed config based on flag values
		flagConfig = &Config{}
		// zeroed config based on file values
		fileConfig = &Config{}
		// zeroed config based on db values
		// if db exists then it's values have precedence before
		// default flag values
		dbConfig = &Config{}
		err      error
	)
	*flagConfig = *r.config
	flagConfig.defToNil()
	fileConfig, err = r.unmarshalConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "couldn't unmarshal config file: %s", err.Error())
		cli.Exit(1)
	}
	err = mergeConfig(fileConfig, flagConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "couldn't merge flags config to file config: %s", err.Error())
		cli.Exit(1)
	}
	// download config from db first
	err = mergeConfig(fileConfig, dbConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "couldn't merge db config to file config: %s", err.Error())
		cli.Exit(1)
	}
	err = mergeConfig(r.config, fileConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "couldn't merge file config to app config: %s", err.Error())
		cli.Exit(1)
	}
	r.logger = logger(*r.config.LogPath)
}

func (r *rootCmd) action() {
	fmt.Println("Works fine!")
}

// Register executes root command
func (r *rootCmd) Register(app *cli.Cli, configBucket, envPrefix string) {
	r.SetGlobalOpts(app, configBucket, envPrefix)
	app.Before = r.before
	app.Action = r.action
}

// Register executes root command through calling internal rootCmd.Bootstrap
func Register(app *cli.Cli, configBucket, envPrefix string) {
	cmd := rootCmd{}
	cmd.Register(app, configBucket, envPrefix)
}

func parseDBConfig(dbConfig string) ([]string, error) {
	ret := []string{}
	i := strings.Index(dbConfig, ":")
	dbType := dbConfig[:i]
	switch dbType {
	case "boltdb", "consul", "dynamodb", "etcd", "redis", "zookeeper":
		ret = append(ret, dbType)
	default:
		return nil, fmt.Errorf("Unsupported store db passed")
	}
	if len(dbConfig) < i+2 {
		return nil, fmt.Errorf("Store db path/address is not provided")
	}
	dbPath := dbConfig[i+1:]
	ret = append(ret, strings.Split(dbPath, ",")...)
	return ret, nil
}

func (r *rootCmd) newStore(dbType string, dbAddr []string) (*svalkey.Store, error) {
	var backend store.Backend
	switch dbType {
	case "consul":
		consul.Register()
		backend = store.CONSUL
	case "etcdv3":
		etcdv3.Register()
		backend = store.ETCDV3
	case "zk":
		zk.Register()
		backend = store.ZK
	case "boltdb":
		boltdb.Register()
		backend = store.BOLTDB
	case "redis":
		redis.Register()
		backend = store.REDIS
	case "dynamodb":
		dynamodb.Register()
		backend = store.DYNAMODB
	default:
		return nil, fmt.Errorf("invalid store db type")
	}
	if r.config.StoreConfig == nil {
		return nil, fmt.Errorf("StoreConfig pointer is nil")
	}
	kv, err := valkeyrie.NewStore(
		backend,
		dbAddr,
		r.config.StoreConfig,
	)
	if err != nil {
		return nil, fmt.Errorf("error create new valkeyrie store: %s", err.Error())
	}
	if r.config.password == nil {
		return nil, fmt.Errorf("nil pointer to password passed")
	}
	if len(*r.config.password) != 32 {
		return nil, fmt.Errorf("invalid length of db password")
	}
	pswd := [32]byte{}
	copy(pswd[:], []byte(*r.config.password))
	sdb, err := svalkey.NewStore(kv, []byte{1, 0}, pswd)
	if err != nil {
		return nil, fmt.Errorf("error create svalkey store: %s", err.Error())
	}
	return sdb, nil
}

func (r *rootCmd) unmarshalConfig() (*Config, error) {
	// Config struct fully listed
	// All values are zeroed
	// default values are set in NewConfig() func
	appConfig := &Config{
		Options: Options{
			HTTPConf: HTTPConf{
				Listen: nil,
				TLS:    nil,
				TLSConfig: TLSConfig{
					CertFile:   nil,
					KeyFile:    nil,
					CACertFile: nil,
				},
			},
			GrpcConf: GrpcConf{
				ListenGrpc: nil,
			},
			KeyGeneration: KeyGeneration{
				Sign: Sign{
					SigAlg:  nil,
					SigBits: nil,
				},
				Encryption: Encryption{
					EncAlg:  nil,
					EncBits: nil,
					ContEnc: nil,
				},
				Expiry: nil,
				JwtTTL: JwtTTL{
					AuthTTL:    nil,
					RefreshTTL: nil,
				},
			},
			SelfName: nil,
			LogPath:  nil,
			DBConfig: nil,
			Verbose:  nil,
		},
		StoreConfig: &store.Config{
			ClientTLS: &store.ClientTLSConfig{
				CertFile:   "",
				KeyFile:    "",
				CACertFile: "",
			},
			TLS:               nil,
			ConnectionTimeout: 0,
			SyncPeriod:        0,
			Bucket:            "",
			PersistConnection: false,
			Username:          "",
			Password:          "",
			Token:             "",
		},
	}
	// d, err := yaml.Marshal(appConfig)
	// if err != nil {
	// 	fmt.Printf("error: %v", err)
	// 	return nil, err
	// }
	// fmt.Printf("--- m dump:\n%s\n\n", string(d))

	// storeConfig := appConfig.StoreConfig
	if r.config.ConfigFile != nil && *r.config.ConfigFile != "" {
		if !r.config.configFileSetByUser {
			// if user didn't provide --file flag and config file
			// in default path doesn't exit then don't return error
			// just return zeroed config struct
			if _, err := os.Stat(*r.config.ConfigFile); err != nil &&
				os.IsNotExist(err) {
				return appConfig, nil
			}
		}
		if filepath.Ext(*r.config.ConfigFile) != ".json" {
			return nil, fmt.Errorf("error unmarshal config: invalid file type")
		}
		content, err := ioutil.ReadFile(*r.config.ConfigFile)
		if err != nil {
			return nil, fmt.Errorf("error reading config file")
		}
		// fmt.Printf("read content of config file:\n%s\n", string(content))
		err = json.Unmarshal(content, appConfig)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling config file: %s", err.Error())
		}
	}
	// Don't set default here, only in config.go in func NewConfig
	// then merge it

	// if storeConfig.ConnectionTimeout == 0 {
	// 	storeConfig.ConnectionTimeout = 3 * time.Second
	// }
	// if storeConfig.Bucket == "" {
	// 	storeConfig.Bucket = r.config.bucketName
	// }
	// storeConfig.PersistConnection = true

	return appConfig, nil
}
