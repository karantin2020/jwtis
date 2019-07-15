package cmd

import (
	"os"
	"testing"

	cli "github.com/jawher/mow.cli"
)

func TestCli_Run(t *testing.T) {
	type fields struct {
		Cli       *cli.Cli
		cmd       *rootCmd
		name      string
		version   string
		bucket    string
		envPrefix string
	}
	type args struct {
		args []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Positive test",
			fields: fields{
				Cli: cli.App("testApp", "test description"),
				cmd: &rootCmd{
					name: "testApp",
				},
				name:      "testApp",
				version:   "v0.0.1",
				bucket:    "testBucket",
				envPrefix: "TEST_",
			},
			args: args{
				args: []string{"asd", "--tls", "-n", "sara",
					"-f./testdata/config.yml",
					"--logPath=./testdata/test.log",
					"-d", "boltdb:./testdata/test.db",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Cli{
				cli:       tt.fields.Cli,
				cmd:       tt.fields.cmd,
				name:      tt.fields.name,
				version:   tt.fields.version,
				bucket:    tt.fields.bucket,
				envPrefix: tt.fields.envPrefix,
			}
			c.Version("V version", "v0.0.1")
			if err := c.Run(tt.args.args); (err != nil) != tt.wantErr {
				t.Errorf("Cli.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	os.Remove("./testdata/test.log")
	os.Remove("./testdata/test.db")
}
