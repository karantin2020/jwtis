package cmd

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"testing"

	cli "github.com/jawher/mow.cli"
	"github.com/karantin2020/jwtis"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestRegister(t *testing.T) {
	type args struct {
		app          *cli.Cli
		configBucket string
		envPrefix    string
	}
	versionTest := cli.App("appName", "appDescription")
	versionTest.Version("V version", "appVersion")
	tests := []struct {
		name   string
		args   args
		osArgs []string
	}{
		{
			name: "Positive test",
			args: args{
				app:          cli.App("appName", "appDescription"),
				configBucket: "bucket",
				envPrefix:    "prefix",
			},
			osArgs: []string{"asd", "--tls", "-n", "sara",
				"-f./testdata/config.yml",
				"-d", "boltdb:./testdata/test.db",
			},
		},
		// {
		// 	name: "Help test",
		// 	args: args{
		// 		app:          cli.App("appName", "appDescription"),
		// 		configBucket: "bucket",
		// 		envPrefix:    "prefix",
		// 	},
		// 	osArgs: []string{"asd", "-h"},
		// },
		// {
		// 	name: "Version test",
		// 	args: args{
		// 		app:          versionTest,
		// 		configBucket: "bucket",
		// 		envPrefix:    "prefix",
		// 	},
		// 	osArgs: []string{"asd", "-V"},
		// },
		// {
		// 	name: "Negative test",
		// 	args: args{
		// 		app:          versionTest,
		// 		configBucket: "bucket",
		// 		envPrefix:    "prefix",
		// 	},
		// 	osArgs: []string{"asd", "-yu"},
		// },
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := rootCmd{}
			cmd.Register(tt.args.app, tt.args.configBucket, tt.args.envPrefix)
			buf := new(bytes.Buffer)
			err := tt.args.app.Run(tt.osArgs)
			assert.Nil(t, err, "app.Run must not return error")
			cmd.logger = zerolog.New(buf)
			assert.NotNil(t, cmd.config, "Config must not be nil")
			assert.Equal(t, zerolog.TimestampFieldName, "t", "Logger must be configured")
			cmd.logger.Log().Msg("test message: " + tt.name)
			assert.Equal(t, buf.String(),
				fmt.Sprintf("{\"m\":\"test message: %s\"}\n", tt.name),
				"Log message must be correct")
			// fmt.Printf("cmd.config:\n%+v\n", cmd.config)
			assert.Equal(t, "sara", *cmd.config.SelfName, "Service name must be equal to 'sara'")
			assert.Equal(t, true, *cmd.config.TLS, "Service TLS must be 'true'")
			assert.NotNil(t, cmd.config.StoreConfig, "cmd.config.StoreConfig must not be nil")
			assert.Equal(t, tt.args.configBucket, cmd.config.bucketName,
				"Store config bucket name must be equal to confTestBucket")
			assert.Equal(t, "127.0.0.1:3435", *cmd.config.Listen)
			assert.Equal(t, "127.0.0.1:3436", *cmd.config.ListenGrpc)
			assert.Equal(t, "72h", *cmd.config.AuthTTL)
			assert.Equal(t, "720h", *cmd.config.RefreshTTL)
		})
	}
	os.Remove("./testdata/test.db")
}

func TestRegisterExisted(t *testing.T) {
	type args struct {
		app          *cli.Cli
		configBucket string
		envPrefix    string
	}
	app := cli.App("appName", "appDescription")
	appCmd := rootCmd{}
	appCmd.Register(app, "bucket", "prefix")
	app.Run([]string{"asd", "-n", "sara",
		"--logPath", "./testdata/test.log",
		"-f./testdata/config.yml",
		"-d", "boltdb:./testdata/test.db",
	})
	pswd := appCmd.password
	hexPswd := hexEncode(pswd[:])
	appCmd.store.Close()
	tests := []struct {
		name   string
		args   args
		osArgs []string
	}{
		{
			name: "Positive test",
			args: args{
				app:          cli.App("appName", "appDescription"),
				configBucket: "bucket",
				envPrefix:    "prefix",
			},
			osArgs: []string{"asd", "-n", "sara",
				"--logPath", "./testdata/test.log",
				"-f./testdata/config.yml",
				"-d", "boltdb:./testdata/test.db",
				"-p", string(hexPswd),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := rootCmd{}
			cmd.Register(tt.args.app, tt.args.configBucket, tt.args.envPrefix)
			err := tt.args.app.Run(tt.osArgs)
			assert.Nil(t, err, "app.Run must not return error")
			cmd.store.Close()
		})
		os.Remove("./testdata/test.db")
	}
}

func Test_parseDBConfig(t *testing.T) {
	type args struct {
		dbConfig string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "Successful test boltdb config",
			args: args{
				`boltdb:./testdata/jwtis.log`,
			},
			want:    []string{"boltdb", "./testdata/jwtis.log"},
			wantErr: false,
		},
		{
			name: "Error test boltdb config",
			args: args{
				`boltdb:a`,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Successful test consul config single",
			args: args{
				`consul:127.0.0.1:8500`,
			},
			want:    []string{"consul", "127.0.0.1:8500"},
			wantErr: false,
		},
		{
			name: "Successful test consul config plural",
			args: args{
				`consul:127.0.0.1:8500,127.0.0.1:8501`,
			},
			want:    []string{"consul", "127.0.0.1:8500", "127.0.0.1:8501"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDBConfig(tt.args.dbConfig)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDBConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseDBConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_rootCmd_newStore(t *testing.T) {
	type fields struct {
		config   *Config
		logger   zerolog.Logger
		keysRepo jwtis.KeysRepository
	}
	type args struct {
		dbType string
		dbAddr []string
	}
	config := NewConfig("testBucket")
	// configFile := ""
	pswd := "12345678123456781234567812345678"
	config.password = &pswd
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    func(assert.TestingT, interface{}, ...interface{}) bool
		wantErr bool
	}{
		{
			name: "Successful boltdb test",
			fields: fields{
				config: config,
			},
			args: args{
				dbType: "boltdb",
				dbAddr: []string{"./testdata/test.db"},
			},
			want:    assert.NotNil,
			wantErr: false,
		},
		{
			name: "Successful etcdv3 test",
			fields: fields{
				config: config,
			},
			args: args{
				dbType: "etcdv3",
				dbAddr: []string{"127.0.0.1:8500"},
			},
			want:    assert.NotNil,
			wantErr: false,
		},
	}
	for i := range tests {
		t.Run(tests[i].name, func(t *testing.T) {
			r := &rootCmd{
				config: tests[i].fields.config,
			}
			got, err := r.newStore(tests[i].args.dbType, tests[i].args.dbAddr)
			if (err != nil) != tests[i].wantErr {
				t.Errorf("rootCmd.newStore() error = %v, wantErr %v", err, tests[i].wantErr)
				return
			}
			tests[i].want(t, got, "New store result must not be nil")
			if tests[i].args.dbType == "boltdb" {
				os.Remove("./testdata/test.db")
			}
			assert.Equal(t, "testBucket", r.config.bucketName)
			// assert.Equal(t, "testBucket", r.config.StoreConfig.Bucket)
		})
	}
}
