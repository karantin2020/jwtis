package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"

	cli "github.com/jawher/mow.cli"
	"github.com/karantin2020/jwtis"
	jose "gopkg.in/square/go-jose.v2"

	"github.com/karantin2020/svalkey"
	// "github.com/rs/zerolog"
	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	"github.com/abronan/valkeyrie"
	"github.com/abronan/valkeyrie/store"

	"github.com/abronan/valkeyrie/store/boltdb"
	"github.com/abronan/valkeyrie/store/consul"

	// "github.com/abronan/valkeyrie/store/dynamodb"
	// etcdv3 "github.com/abronan/valkeyrie/store/etcd/v3"
	"github.com/abronan/valkeyrie/store/redis"
	zk "github.com/abronan/valkeyrie/store/zookeeper"

	"encoding/json"

	"gopkg.in/yaml.v3"

	// grpcs "github.com/karantin2020/jwtis/cmd/service"
	"github.com/karantin2020/jwtis/svc"
	group "github.com/oklog/run"

	"go.uber.org/zap"
)

const (
	configStoreKey  = "jwtis.cmd.config"
	keysStorePrefix = "jwtis.keysRepo"
	// configCheckKey = "jwtis.cmd.check.key"
	// checkValLength = 256
)

var (
	log             kitlog.Logger
	cancelInterrupt chan struct{}
)

type rootCmd struct {
	// config holds app config parameters
	config *Config
	// logger is the app logger
	logger kitlog.Logger
	// store is the db config to store
	// configs and keys
	store *svalkey.Store
	// internal password
	password [32]byte
	// exists shows whether app exists or not
	exists        bool
	name, version string
}

// // CheckValType stores secretString to check
// type CheckValType struct {
// 	Val [checkValLength]byte
// }

// SetGlobalOpts sets global cli options
func (r *rootCmd) SetGlobalOpts(app *cli.Cli, configBucket, envPrefix string) {
	if !strings.HasSuffix(envPrefix, "_") {
		envPrefix = envPrefix + "_"
	}
	app.Spec = "[-cmgearnpdv] [--tls] [--certFile] [--keyFile] [--caCertFile]" +
		" [--sigAlg] [--sigBits] [--encAlg] [--encBits] [--contEnc] [--logPath]"
	confRepo := NewConfig(configBucket)
	confRepo.ListenMetrics = app.String(cli.StringOpt{
		Name:      "m metricsAddr",
		Value:     "127.0.0.1:4343",
		Desc:      "string Http ip:port to listen to for metrics",
		EnvVar:    envPrefix + "HTTP_ADDRESS",
		SetByUser: &confRepo.listenSetByUser,
	})
	confRepo.ListenGrpc = app.String(cli.StringOpt{
		Name:      "g grpcAddr",
		Value:     "127.0.0.1:40430",
		Desc:      "string Grpc ip:port to listen to for service communication",
		EnvVar:    envPrefix + "GRPC_ADDRESS",
		SetByUser: &confRepo.listenGrpcSetByUser,
	})
	confRepo.TLS = app.Bool(cli.BoolOpt{
		Name:      "tls",
		Value:     false,
		Desc:      "bool Use tls connection [not implemented yet]",
		EnvVar:    envPrefix + "TLS",
		SetByUser: &confRepo.tlsSetByUser,
	})

	confRepo.CertFile = app.String(cli.StringOpt{
		Name:      "certFile",
		Value:     "",
		Desc:      "string Default CertFile for tls",
		EnvVar:    envPrefix + "CERT_FILE",
		SetByUser: &confRepo.certFileSetByUser,
	})
	confRepo.KeyFile = app.String(cli.StringOpt{
		Name:      "keyFile",
		Value:     "",
		Desc:      "string Default KeyFile for tls",
		EnvVar:    envPrefix + "KEY_FILE",
		SetByUser: &confRepo.keyFileSetByUser,
	})
	confRepo.CACertFile = app.String(cli.StringOpt{
		Name:      "caCertFile",
		Value:     "",
		Desc:      "string Default CACertFile for tls",
		EnvVar:    envPrefix + "CA_CERT_FILE",
		SetByUser: &confRepo.caCertFileSetByUser,
	})

	confRepo.SigAlg = app.String(cli.StringOpt{
		Name:      "sigAlg",
		Value:     "ES256",
		Desc:      "string Default algorithm to be used for sign. Possible values are: ES256 ES384 ES512 EdDSA RS256 RS384 RS512 PS256 PS384 PS512",
		EnvVar:    envPrefix + "SIG_ALG",
		SetByUser: &confRepo.sigAlgSetByUser,
	})
	confRepo.SigBits = app.Int(cli.IntOpt{
		Name:      "sigBits",
		Value:     256,
		Desc:      "int Default key size in bits for sign key. Supported elliptic bit lengths are 256, 384, 521",
		EnvVar:    envPrefix + "SIG_BITS",
		SetByUser: &confRepo.sigBitsSetByUser,
	})
	confRepo.EncAlg = app.String(cli.StringOpt{
		Name:      "encAlg",
		Value:     "ECDH-ES+A256KW",
		Desc:      "string Default algorithm to be used for encrypt. Possible values are RSA1_5 RSA-OAEP RSA-OAEP-256 ECDH-ES ECDH-ES+A128KW ECDH-ES+A192KW ECDH-ES+A256KW",
		EnvVar:    envPrefix + "ENC_ALG",
		SetByUser: &confRepo.encAlgSetByUser,
	})
	confRepo.EncBits = app.Int(cli.IntOpt{
		Name:      "encBits",
		Value:     256,
		Desc:      "int Default key size in bits for encrypt. Supported elliptic bit lengths are 256, 384, 521",
		EnvVar:    envPrefix + "ENC_BITS",
		SetByUser: &confRepo.encBitsSetByUser,
	})
	confRepo.ContEnc = app.String(cli.StringOpt{
		Name:      "contEnc",
		Value:     "A256GCM",
		Desc:      "string Default content encryption. Possible values are A128GCM, A192GCM, A256GCM",
		EnvVar:    envPrefix + "CONT_ENC",
		SetByUser: &confRepo.contEncSetByUser,
	})
	confRepo.Expiry = app.String(cli.StringOpt{
		Name:      "e expiry",
		Value:     "4320h",
		Desc:      "string Default keys time to live, expiration time [Duration string]",
		EnvVar:    envPrefix + "EXPIRY",
		SetByUser: &confRepo.expirySetByUser,
	})
	confRepo.AuthTTL = app.String(cli.StringOpt{
		Name:      "a authTTL",
		Value:     "72h",
		Desc:      "string Default auth JWT token time to live, expiration time [Duration string]",
		EnvVar:    envPrefix + "AUTH_TTL",
		SetByUser: &confRepo.authTTLSetByUser,
	})
	confRepo.RefreshTTL = app.String(cli.StringOpt{
		Name:      "r refreshTTL",
		Value:     "720h",
		Desc:      "string Default refresh JWT token time to live, expiration time [Duration string]",
		EnvVar:    envPrefix + "REFRESH_TTL",
		SetByUser: &confRepo.refreshTTLSetByUser,
	})

	confRepo.SelfName = app.String(cli.StringOpt{
		Name:      "n name",
		Value:     "JWTIS",
		Desc:      "string Name of this service",
		EnvVar:    envPrefix + "NAME",
		SetByUser: &confRepo.selfNameSetByUser,
	})
	confRepo.password = app.String(cli.StringOpt{
		Name:      "p pswd",
		Value:     "",
		Desc:      "string Storage password. App generates password with db creation. Later user must provide a password to access the database",
		EnvVar:    envPrefix + "PSWD",
		SetByUser: &confRepo.passwordSetByUser,
	})
	confRepo.DBConfig = app.String(cli.StringOpt{
		Name:      "d dbConfig",
		Value:     boltDBConfig,
		Desc:      "string Config to setup db",
		EnvVar:    envPrefix + "DB_CONFIG",
		SetByUser: &confRepo.dbConfigSetByUser,
	})
	confRepo.ConfigFile = app.String(cli.StringOpt{
		Name:      "c config",
		Value:     "./data/config.json",
		Desc:      "string Path to config file",
		EnvVar:    envPrefix + "CONFIG_FILE",
		SetByUser: &confRepo.configFileSetByUser,
	})
	confRepo.LogPath = app.String(cli.StringOpt{
		Name:      "logPath",
		Value:     "./data/jwtis.log",
		Desc:      "string Path to store logs",
		EnvVar:    envPrefix + "LOG_PATH",
		SetByUser: &confRepo.logPathSetByUser,
	})
	confRepo.Verbose = app.Bool(cli.BoolOpt{
		Name:      "v verbose",
		Value:     false,
		Desc:      "bool Verbose. Show detailed logs",
		EnvVar:    envPrefix + "VERBOSE",
		SetByUser: &confRepo.verboseSetByUser,
	})
	r.config = confRepo
}

func (r *rootCmd) Logger() kitlog.Logger {
	return r.logger
}

func (r *rootCmd) loadConfig() {
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

	err = r.loadPassword(flagConfig)
	exitIfError(err, "error load password")

	fileConfig, err = r.unmarshalConfig()
	exitIfError(err, "error unmarshal config file")
	// err = mergeConfig(fileConfig, flagConfig)
	// exitIfError(err, "error merge flags config to file config")

	dbConfig, err = r.loadStore(flagConfig)
	exitIfError(err, "error load store config")

	err = mergeConfig(fileConfig, dbConfig)
	exitIfError(err, "error merge db config to file config")

	err = mergeConfig(r.config, fileConfig)
	exitIfError(err, "error merge file config to app config")
	err = mergeConfig(r.config, flagConfig)
	exitIfError(err, "error merge flags config to app config")
	err = r.config.validate()
	exitIfError(err, "error validate app config")
	// d, err := json.MarshalIndent(r.config, "", "  ")
	// exitIfError(err, "error marshal config")
	// fmt.Println("Config:\n", string(d))
	// r.logger = logger(*r.config.LogPath)
	err = r.store.Put(configStoreKey, r.config, nil)
	exitIfError(err, "error save apps config")
	if log != nil {
		level.Info(log).Log("event", "saved config to db")
	}
}

func (r *rootCmd) loadPassword(flagConfig *Config) error {
	var err error
	if flagConfig.password == nil {
		r.password, err = newPassword()
		if err != nil {
			return fmt.Errorf("error generate new password: %s", err.Error())
		}
		return nil
	}
	decPswd, err := decodeBytes([]byte(*flagConfig.password))
	if err != nil {
		return fmt.Errorf("error hex decode input password: %s", err.Error())
	}
	if len(decPswd) != 32 {
		return fmt.Errorf("error input password length: length is not equal to 32 byte")
	}
	copy(r.password[:], decPswd)
	for i := range decPswd {
		decPswd[i] = 0
	}
	flagConfig.password = nil
	return nil
}

func (r *rootCmd) loadStore(flagConfig *Config) (*Config, error) {
	var (
		// zeroed config based on db values
		// if db exists then it's values have precedence before
		// default flag values
		dbConfig = &Config{}
		err      error
	)
	// download config from db first
	dbTypeAddr, err := parseDBConfig(*r.config.DBConfig)
	if err != nil {
		return nil, fmt.Errorf("error parse db config: %s", err.Error())
	}
	r.store, err = r.newStore(dbTypeAddr[0], dbTypeAddr[1:])
	if err != nil {
		return nil, fmt.Errorf("error get new *svalkey.Store: %s", err.Error())
	}

	err = r.checkStoreConsistency()
	if err != nil {
		return nil, fmt.Errorf("error load store, non consistant: %s", err.Error())
	}
	if r.exists {
		err = r.store.Get(configStoreKey, dbConfig, &store.ReadOptions{
			Consistent: true,
		})
		if err != nil {
			return nil, fmt.Errorf("error get config from store: %s", err.Error())
		}
		// fmt.Println("...downloaded db config")
	}
	return dbConfig, nil
}

func (r *rootCmd) checkStoreConsistency() error {
	if r.store == nil {
		return fmt.Errorf("error check store consistency: store is nil pointer")
	}
	var err error
	r.exists, err = r.store.Exists(configStoreKey, &store.ReadOptions{
		Consistent: true,
	})
	if err != nil && err != store.ErrKeyNotFound {
		return fmt.Errorf("error check store consistency: %s", err.Error())
	}
	// if r.exists {
	// 	fmt.Println("...store exists")
	// }
	return nil
}

func exitIfError(err error, msg string) {
	if err != nil {
		if log != nil {
			level.Error(log).Log("exit", err)
		}
		fmt.Fprintf(os.Stderr, msg+": %s\n", err.Error())
		cli.Exit(1)
	}
}

// func (r *rootCmd) saveAndExitIfError(err error, msg string) {
// 	if err != nil {
// 		log.Error().Err(err).Msg(msg)
// 		err = r.store.Put(configStoreKey, r.config, nil)
// 		if err != nil {
// 			log.Error().Err(err).Msg("error store config in db while exiting")
// 		}
// 		cli.Exit(1)
// 	}
// }

func checkError(err error, msg string) error {
	if err != nil {
		return fmt.Errorf(msg+": %s", err.Error())
	}
	return nil
}

func (r *rootCmd) before() {
	// zerolog.SetGlobalLevel(zerolog.WarnLevel)
	var logger kitlog.Logger
	logger = kitlog.NewLogfmtLogger(kitlog.NewSyncWriter(os.Stderr))
	logger = kitlog.With(logger, "ts", kitlog.DefaultTimestampUTC)
	if *r.config.Verbose {
		// zerolog.SetGlobalLevel(zerolog.InfoLevel)
		logger = level.NewFilter(logger, level.AllowDebug())
	} else {
		logger = level.NewFilter(logger, level.AllowInfo())
	}
	log = logger

	r.loadConfig()

	// r.logger = logger(*r.config.LogPath)
	// log = r.logger.With().Str("sub", "rootCmd").Logger()

	r.greetingMsg()
	if *r.config.Verbose {
		r.config.printConfigs()
	}
}

func (r *rootCmd) action() {
	zlogger, _ := zap.NewProduction()
	defer zlogger.Sync() // flushes buffer, if any
	sugar := zlogger.Sugar()
	sugar.Infow("failed to fetch URL",
		// Structured context as loosely typed key-value pairs.
		"url", "https://google.com",
		"attempt", 3,
		"backoff", time.Second,
	)
	sugar.Infof("Failed to fetch URL: %s", "https://google.com")
	zlogger.Info("failed to fetch URL",
		// Structured context as strongly typed Field values.
		zap.String("url", "https://google.com"),
		zap.Int("attempt", 3),
		zap.Duration("backoff", time.Second),
	)

	level.Info(log).Log("event", "start jwtis service")

	opts, err := r.config.getKeysRepoOptions()
	exitIfError(err, "error prepare keys repo options")
	keysRepo, err := jwtis.NewKeysRepo(&jwtis.KeysRepoOptions{
		Store:  r.store,
		Prefix: keysStorePrefix,
		Opts:   opts,
	})
	exitIfError(err, "error create keys repository; exit")
	// if err != nil {
	// 	log.Error().Err(err).Msg("error create keys repository; exit")
	// 	// err = r.store.Put(configStoreKey, r.config, nil)
	// 	// if err != nil {
	// 	// 	log.Error().Err(err).Msg("error store config in db while exiting")
	// 	// }
	// 	cli.Exit(1)
	// }

	// grpcs.RunServer(*r.config.Listen, *r.config.ListenGrpc,
	// 	keysRepo, jose.ContentEncryption(*r.config.ContEnc))
	cancelInterrupt = make(chan struct{})
	svc.Run(svc.ServerOpts{
		MetricsAddr:     *r.config.ListenMetrics,
		Addr:            *r.config.ListenGrpc,
		KeysRepo:        keysRepo,
		ContEnc:         jose.ContentEncryption(*r.config.ContEnc),
		Logger:          log,
		G:               &group.Group{},
		CancelInterrupt: cancelInterrupt,
	})

	// srv, err := server.NewJWTISServer(*r.config.Listen,
	// 	*r.config.ListenGrpc, keysRepo,
	// 	&r.logger, jose.ContentEncryption(*r.config.ContEnc))
	// exitIfError(err, "error in setup http server")
	// var g errgroup.Group
	// g.Go(func() error {
	// 	err = srv.Run()
	// 	if err != nil && err != http.ErrServerClosed {
	// 		log.Error().Err(err).Msg("run server error")
	// 		return err
	// 	}
	// 	return nil
	// })
	// g.Go(func() error {
	// 	// Wait for interrupt signal to gracefully shutdown the server with
	// 	// a timeout of 5 seconds.
	// 	quit := make(chan os.Signal, 1)
	// 	// kill (no param) default send syscanll.SIGTERM
	// 	// kill -2 is syscall.SIGINT
	// 	// kill -9 is syscall. SIGKILL but can"t be catch, so don't need add it
	// 	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	// 	<-quit
	// 	fmt.Print("\r")
	// 	log.Info().Msg("shutdown server on signal")
	// 	// TODO: add shutdown timeout app option
	// 	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	// 	defer cancel()
	// 	err := srv.Shutdown(ctx)
	// 	if err != nil {
	// 		log.Error().Err(err).Msg("server shutdown error")
	// 	}
	// 	log.Info().Msg("http server gracefully shutdown")
	// 	return nil
	// })
	// g.Wait()
	level.Info(log).Log("event", "jwtis finished work")
}

func (r *rootCmd) after() {
	if r.store != nil && r.store.Store != nil {
		err := r.store.Put(configStoreKey, r.config, nil)
		for i := range r.password {
			r.password[i] = 0
		}
		exitIfError(err, "error save apps config")
		level.Info(log).Log("event", "saved config to db")
	}
}

// Register executes root command
func (r *rootCmd) Register(app *cli.Cli, configBucket, envPrefix string) {
	r.SetGlobalOpts(app, configBucket, envPrefix)
	app.Before = r.before
	app.Action = r.action
	app.After = r.after
}

// Register executes root command through calling internal rootCmd.Bootstrap
func Register(app *cli.Cli, configBucket, envPrefix string) {
	cmd := rootCmd{}
	cmd.Register(app, configBucket, envPrefix)
}

// dbConfig must be in format:
// `boltdb:./data/store.db`
// or
// `consul:127.0.0.1:8500`
func parseDBConfig(dbConfig string) ([]string, error) {
	ret := []string{}
	// i := strings.Index(dbConfig, ":")
	sConf := strings.SplitN(dbConfig, ":", 2)
	if len(sConf) != 2 {
		return nil, fmt.Errorf("invalid dbConfig string passed")
	}
	dbType := sConf[0]
	switch dbType {
	case "boltdb", "consul" /*"dynamodb",*/, "etcd", "redis", "zookeeper":
		ret = append(ret, dbType)
	default:
		return nil, fmt.Errorf("unsupported store db passed")
	}
	if len(sConf[1]) < 2 {
		return nil, fmt.Errorf("Store db path/address is not provided")
	}
	ret = append(ret, strings.Split(sConf[1], ",")...)
	return ret, nil
}

func (r *rootCmd) newStore(dbType string, dbAddr []string) (*svalkey.Store, error) {
	var backend store.Backend
	switch dbType {
	case "consul":
		consul.Register()
		backend = store.CONSUL
	// case "etcdv3":
	// 	etcdv3.Register()
	// 	backend = store.ETCDV3
	case "zk":
		zk.Register()
		backend = store.ZK
	case "boltdb":
		boltdb.Register()
		backend = store.BOLTDB
	case "redis":
		redis.Register()
		backend = store.REDIS
	// case "dynamodb":
	// 	dynamodb.Register()
	// 	backend = store.DYNAMODB
	default:
		return nil, errors.New("invalid store db type")
	}
	if r.config.StoreConfig == nil {
		return nil, errors.New("StoreConfig pointer is nil")
	}
	storeConf, err := r.config.GetStoreConfig()
	if err != nil {
		return nil, errors.New("error in newStore, couldn't create *store.Config: " +
			err.Error())
	}
	kv, err := valkeyrie.NewStore(
		backend,
		dbAddr,
		storeConf,
	)
	if err != nil {
		return nil, errors.New("error create new valkeyrie store: " + err.Error())
	}
	sdb, err := svalkey.NewJSONStore(kv, []byte{1, 0}, r.password)
	if err != nil {
		return nil, errors.New("error create svalkey store: " + err.Error())
	}
	// for i := range r.password {
	// 	r.password[i] = 0
	// }
	return sdb, nil
}

func (r *rootCmd) unmarshalConfig() (*Config, error) {
	// Config struct fully listed
	// All values are zeroed
	// default values are set in NewConfig() func
	appConfig := &Config{
		Options: Options{
			HTTPConf: HTTPConf{
				ListenMetrics: nil,
				TLS:           nil,
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
		StoreConfig: &StoreConfig{
			ClientTLS: &StoreClientTLSConfig{
				CertFile:           "",
				KeyFile:            "",
				CACertFile:         "",
				InsecureSkipVerify: false,
			},
			ConnectionTimeout: "",
			SyncPeriod:        "",
			// Bucket:            "",
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
		var unmarshalFunc func(data []byte, v interface{}) error
		switch filepath.Ext(*r.config.ConfigFile) {
		case ".json":
			unmarshalFunc = json.Unmarshal
		case ".yml", ".yaml":
			unmarshalFunc = yaml.Unmarshal
		default:
			return nil, errors.New("error unmarshal config: invalid file type")
		}
		content, err := ioutil.ReadFile(*r.config.ConfigFile)
		if err != nil {
			return nil, errors.New("error reading config file")
		}
		// fmt.Printf("read content of config file:\n%s\n", string(content))
		err = unmarshalFunc(content, appConfig)
		if err != nil {
			return nil, errors.New("error unmarshalling config file: " + err.Error())
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
