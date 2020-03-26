package cmd_test

import (
	"os"
	"testing"

	cli "github.com/jawher/mow.cli"
	"github.com/karantin2020/jwtis/cmdz/cmd"
	"github.com/stretchr/testify/assert"
)

func TestRegisterExternalNewPswd(t *testing.T) {
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
				"--logPath=./testdata/test.log",
				"-d", "boltdb:./testdata/test.db",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd.Register(tt.args.app, tt.args.configBucket, tt.args.envPrefix)
			err := tt.args.app.Run(tt.osArgs)
			assert.Nil(t, err, "app.Run must not return error")
		})
	}
	os.Remove("./testdata/test.log")
	os.Remove("./testdata/test.db")
}
