package main

import (
	"bytes"
	"fmt"
	"time"

	bolt "github.com/coreos/bbolt"
	cli "github.com/jawher/mow.cli"
	"github.com/karantin2020/jwtis"
	jose "gopkg.in/square/go-jose.v2"
)

// DefaultValues hold default key config values
type DefaultValues struct {
	SigAlg     string                 // Default algorithm to be used for sign
	SigBits    int                    // Default key size in bits for sign
	EncAlg     string                 // Default algorithm to be used for encrypt
	EncBits    int                    // Default key size in bits for encrypt
	ContEnc    jose.ContentEncryption // Default Content Encryption
	Expiry     time.Duration          // Default value for keys ttl
	AuthTTL    time.Duration          // Default value for auth jwt ttl
	RefreshTTL time.Duration          // Default value for refresh jwt ttl
}

// http config
type configs struct {
	Listen     string // ip:port to listen to
	ListenGrpc string // grpc ip:port to listen to
	TLS        bool   // Future feature
	DefaultValues
	SelfName []byte
}

type internalVars struct {
	dbCheckValue []byte
	password     []byte
	nonce        []byte
	encKey       jwtis.Key
}

type internalRepository struct {
	// configs
	configs

	internalVars
	repoDB     *bolt.DB
	confRepo   *configRepository
	bucketName []byte
}

type nonceCheck struct {
	Nonce    []byte
	CheckKey []byte
}

type mackey struct {
	jwtis.MACKey `json:"mac"`
}

var (
	internalPassword = []byte("jwtis.internal.password")
	internalNonce    = []byte("jwtis.internal.nonce")
	internalEncKey   = []byte("jwtis.internal.enckey")
	internalConfigs  = []byte("jwtis.internal.configs")
	dbCheckKey       = []byte("jwtis.internal.dbCheckKey")
	dbCheckValue     = []byte("jwtis.internal.dbCheckValue")
	dbExists         bool
	dbCheckFault     bool
)

func (p *internalRepository) init(db *bolt.DB, confRepo *configRepository) {
	if p == nil {
		log.Info().Msg("internalRepository pointer is nil")
		cli.Exit(1)
	}
	if db == nil {
		log.Info().Msg("internalRepository db pointer is nil")
		cli.Exit(1)
	}
	if confRepo == nil {
		log.Info().Msg("internalRepository confRepo pointer is nil")
		cli.Exit(1)
	}
	p.bucketName = buckets["internalBucketName"]
	p.repoDB = db
	p.confRepo = confRepo
	p.setPassword([]byte(*confRepo.password))

	err := p.load()
	if err != nil {
		log.Error().Err(err).Msg("can't load internalRepo from boltDB; exit")
		cli.Exit(1)
	}

	if !dbExists || confRepo.selfNameSetByUser {
		p.SelfName = []byte(*confRepo.selfName)
	}
	if !dbExists || confRepo.listenSetByUser {
		p.Listen = *confRepo.listen
	}
	if !dbExists || confRepo.listenGrpcSetByUser {
		p.ListenGrpc = *confRepo.listenGrpc
	}
	if !dbExists || confRepo.tlsSetByUser {
		p.TLS = *confRepo.tls
	}
	if !dbExists || confRepo.sigAlgSetByUser {
		p.SigAlg = *confRepo.sigAlg
	}
	if !dbExists || confRepo.sigBitsSetByUser {
		p.SigBits = *confRepo.sigBits
	}
	if !dbExists || confRepo.encAlgSetByUser {
		p.EncAlg = *confRepo.encAlg
	}
	if !dbExists || confRepo.encBitsSetByUser {
		p.EncBits = *confRepo.encBits
	}
	if !dbExists || confRepo.contEncSetByUser || p.ContEnc == "" {
		p.ContEnc = jose.ContentEncryption(*confRepo.contEnc)
	}
	if !dbExists || confRepo.expirySetByUser || p.Expiry == 0 {
		p.Expiry, err = time.ParseDuration(*confRepo.expiry)
		if err != nil {
			log.Error().Err(err).Msg("can't parse Expiry duration; exit")
			cli.Exit(1)
		}
	}
	if !dbExists || confRepo.authTTLSetByUser || p.AuthTTL == 0 {
		p.AuthTTL, err = time.ParseDuration(*confRepo.authTTL)
		if err != nil {
			log.Error().Err(err).Msg("can't parse AuthTTL duration; exit")
			cli.Exit(1)
		}
	}
	if !dbExists || confRepo.refreshTTLSetByUser || p.RefreshTTL == 0 {
		p.RefreshTTL, err = time.ParseDuration(*confRepo.refreshTTL)
		if err != nil {
			log.Error().Err(err).Msg("can't parse RefreshTTL duration; exit")
			cli.Exit(1)
		}
	}
	if err = p.validate(); err != nil {
		fmt.Printf("error configuration validating:\n%s\n", err)
		cli.Exit(1)
	}
	if err := p.save(); err != nil {
		log.Error().Err(err).Msg("can't save internalRepo; exit")
		cli.Exit(1)
	}
}

func (p internalRepository) printConfigs() {
	fmt.Printf("Current configuration:\n")
	fmt.Printf("  internalRepo.configs.listen:\t\t%s\n", p.Listen)
	fmt.Printf("  internalRepo.configs.listenGrpc:\t%s\n", p.ListenGrpc)
	fmt.Printf("  internalRepo.configs.tls:\t\t%t\n", p.TLS)
	fmt.Printf("  internalRepo.configs.sigAlg:\t\t%s\n", p.SigAlg)
	fmt.Printf("  internalRepo.configs.sigBits:\t\t%d\n", p.SigBits)
	fmt.Printf("  internalRepo.configs.encAlg:\t\t%s\n", p.EncAlg)
	fmt.Printf("  internalRepo.configs.encBits:\t\t%d\n", p.EncBits)
	fmt.Printf("  internalRepo.configs.contEnc:\t\t%s\n", p.ContEnc)
	fmt.Printf("  internalRepo.configs.selfName:\t%s\n", string(p.SelfName))
	fmt.Printf("  internalRepo.configs.expiry:\t\t%s\n", p.Expiry)
	fmt.Printf("  internalRepo.configs.authTTL:\t\t%s\n", p.AuthTTL)
	fmt.Printf("  internalRepo.configs.refreshTTL:\t%s\n", p.RefreshTTL)
	// fmt.Printf("internalRepo.configs.password: '%s'\n", string(p.password))
	fmt.Printf("  confRepo.options.dbPath:\t\t%s\n", *confRepo.dbPath)
}

func (p *internalRepository) setDB(db *bolt.DB) *internalRepository {
	p.repoDB = db
	return p
}

func (p *internalRepository) setPassword(psw []byte) *internalRepository {
	p.password = append(p.password[:0], psw...)
	copy(p.encKey.EncryptionKey[:], []byte(psw))
	return p
}

func (p *internalRepository) save() error {
	if p.repoDB == nil {
		return errDBNotSet
	}
	if err := boltDB.Batch(func(tx *bolt.Tx) error {
		b := tx.Bucket(p.bucketName)
		key := mackey{
			MACKey: p.encKey.MACKey,
		}
		if err := save(b, internalEncKey, key); err != nil {
			return err
		}
		// buf := make([]byte, 0, len(dbCheckValue)+jwtis.Extension+len(p.nonce))
		// ciphertext := p.encKey.Seal(buf[:0], p.nonce, dbCheckValue, nil)
		// nk := append(append([]byte{}, p.nonce...), ciphertext...)
		nk := p.sealWithNonce(dbCheckValue)
		if err := saveByte(b, dbCheckKey, nk); err != nil {
			return err
		}
		if err := jwtis.SaveSealed(&p.encKey, p.nonce, b, internalConfigs, p.configs); err != nil {
			return err
		}
		// log.Printf("saved internal configs: '%+v'\n", p.configs)
		return nil
	}); err != nil {
		return fmt.Errorf("%s: %s", errSaveDBInternal.Error(), err.Error())
	}
	return nil
}

func (p *internalRepository) sealWithNonce(in []byte) []byte {
	buf := make([]byte, 0, len(in)+jwtis.Extension+len(p.nonce))
	ciphertext := p.encKey.Seal(buf[:0], p.nonce, in, nil)
	nk := append(append([]byte{}, p.nonce...), ciphertext...)
	return nk
}

func (p *internalRepository) load() error {
	if p.repoDB == nil {
		return errDBNotSet
	}
	dbExists = true
	// log.Printf("enc key is: '%+v'", p.encKey)
	// log.Printf("enc key secret is: '%s'", string(p.encKey.EncryptionKey[:]))
	if err := boltDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(p.bucketName)
		if err := load(b, internalEncKey, &p.encKey); err != nil {
			if err == errKeyNotFound {
				return errEncKeyNotFound
			}
			return err
		}
		// log.Printf("loaded enc key is: '%+v'", p.encKey)
		nk := []byte{}
		if err := loadByte(b, dbCheckKey, &nk); err != nil {
			if err == errKeyNotFound {
				return errCheckKeyNotFound
			}
			return fmt.Errorf("error loading dbCheckValue: %s", err.Error())
		}
		// nonce, ciphertext := nk[:p.encKey.NonceSize()], nk[p.encKey.NonceSize():]
		// plaintext, err := p.encKey.Open(ciphertext[:0], nonce, ciphertext, nil)
		var err error
		p.dbCheckValue, p.nonce, err = p.openWithNonce(nk)
		if err != nil {
			return err
		}
		// p.nonce = append([]byte{}, nonce...)
		if err := jwtis.LoadSealed(&p.encKey, p.nonce, b, internalConfigs, &p.configs); err != nil {
			return fmt.Errorf("error loading internalConfigs: %s", err.Error())
		}
		// log.Printf("loaded internal configs: '%+v'\n", p.configs)
		return nil
	}); err != nil {
		if err != errCheckKeyNotFound && err != errEncKeyNotFound {
			if err == jwtis.ErrInvalidEncKey && *p.confRepo.password == "" {
				FatalF("db password must be inserted")
			}
			return fmt.Errorf("%s: %s", errLoadDBInternal.Error(), err.Error())
		}
		dbExists = false
		newDBPassword()
	}
	if dbExists && !bytes.Equal(p.dbCheckValue, dbCheckValue) {
		// log.Printf("p.dbCheckValue is: '%s'\n", p.dbCheckValue)
		// log.Printf("dbCheckValue is: '%s'\n", dbCheckValue)
		FatalF(errIncorrectPassword.Error())
	}
	return nil
}

func (p *internalRepository) openWithNonce(in []byte) ([]byte, []byte, error) {
	nonce, ciphertext := in[:p.encKey.NonceSize()], in[p.encKey.NonceSize():]
	plaintext, err := p.encKey.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		return nil, nil, err
	}
	return append([]byte{}, plaintext...), append([]byte{}, nonce...), nil
}

func newDBPassword() {
	internalsRepo.password = getPassword(passwordLength)
	internalsRepo.nonce = jwtis.NewRandomNonce()
	internalsRepo.encKey.Init()
	if len(internalsRepo.encKey.EncryptionKey) != len(internalsRepo.password) {
		FatalF("wrong lengths of internalsRepo.encKey.EncryptionKey or internalsRepo.password\n")
	}
	copy(internalsRepo.encKey.EncryptionKey[:], internalsRepo.password)
}

func (p internalRepository) validate() error {
	var mErr jwtis.Error

	switch p.SigAlg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		if p.SigBits != 0 && p.SigBits < 2048 {
			mErr.Append(f(errInvalidSigBitsValue, p.SigAlg, p.SigBits))
		}
	case "ES256", "ES384", "ES512", "EdDSA":
		keylen := map[string]int{
			"ES256": 256,
			"ES384": 384,
			"ES512": 521,
			"EdDSA": 256,
		}
		if p.SigBits != 0 && p.SigBits != keylen[p.SigAlg] {
			mErr.Append(f(errInvalidSigBitsValueA, p.SigAlg, p.SigBits))
		}
	default:
		mErr.Append(errInvalidSigConfig)
	}

	switch p.EncAlg {
	case "RSA1_5", "RSA-OAEP", "RSA-OAEP-256":
		if p.EncBits != 0 && p.EncBits < 2048 {
			mErr.Append(f(errInvalidEncBitsValue, p.EncAlg, p.EncBits))
		}
	case "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW":
		if !containsInt(bits, p.EncBits) {
			mErr.Append(f(errInvalidEncBitsValueA, p.EncAlg, p.EncBits))
		}
	default:
		mErr.Append(errInvalidEncConfig)
	}

	switch p.ContEnc {
	case jose.A128GCM, jose.A192GCM, jose.A256GCM:
	default:
		mErr.Append(errInvalidContEnc)

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
