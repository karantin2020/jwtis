package cmd

import (
	"fmt"

	cli "github.com/jawher/mow.cli"
	client "github.com/karantin2020/jwtis/client/pkg/client"
	"github.com/karantin2020/jwtis/client/pkg/version"
	"go.uber.org/zap"
)

const (
	envPrefix = "JCLI_"
)

var (
	grpcHostAndPort = "127.0.0.1:40430"
	log             *zap.Logger
	app             *cli.Cli
	remote          client.Client
)

var (
	listenOpt     *string
	tlsOpt        *bool
	certFileOpt   *string
	keyFileOpt    *string
	caCertFileOpt *string
)

// Cmd returns configured client
func Cmd(logger *zap.Logger) *cli.Cli {
	log = logger.With(zap.String("command", "root"))

	app = cli.App("cli", "JWTIS client")
	setupOptions()
	app.Before = before
	app.Command("v version", "print app version", cli.ActionCommand(printVersion))
	app.Command("k keys", "execute keys operations", keysCmd)
	app.Command("j jwt", "jwt operations", jwtCmd)
	return app
}

func printVersion() {
	v, err := remote.Version()
	if err != nil {
		log.Info("unable to fetch jwtis version", zap.Error(err))
		cli.Exit(1)
	}
	info := fmt.Sprintf(`
Server info:
  Version: %v
  Checksum: %x
  LastCommitSHA: %v
  LastCommitTime: %v
  BuildTime: %v
  GitBranch: %v
  GoVersion: %v
`, v.Version, v.Checksum, v.LastCommitSHA, v.LastCommitTime, v.BuildTime, v.GitBranch, v.GoVersion)
	info += fmt.Sprintf(`
Client info:%s`, version.BuildDetails())
	fmt.Println(info)
}

func setupOptions() {
	listenOpt = app.String(cli.StringOpt{
		Name:   "l listen",
		Value:  grpcHostAndPort,
		Desc:   "string Grpc ip:port to listen to for service communication",
		EnvVar: envPrefix + "LISTEN",
	})
	tlsOpt = app.Bool(cli.BoolOpt{
		Name:   "tls",
		Value:  false,
		Desc:   "bool Use tls connection [not implemented yet]",
		EnvVar: envPrefix + "TLS",
	})

	certFileOpt = app.String(cli.StringOpt{
		Name:   "certFile",
		Value:  "",
		Desc:   "string Default CertFile for tls",
		EnvVar: envPrefix + "CERT_FILE",
	})
	keyFileOpt = app.String(cli.StringOpt{
		Name:   "keyFile",
		Value:  "",
		Desc:   "string Default KeyFile for tls",
		EnvVar: envPrefix + "KEY_FILE",
	})
	caCertFileOpt = app.String(cli.StringOpt{
		Name:   "caCertFile",
		Value:  "",
		Desc:   "string Default CACertFile for tls",
		EnvVar: envPrefix + "CA_CERT_FILE",
	})
}

func before() {
	var err error
	remote, err = client.New(*listenOpt)
	if err != nil {
		if err == client.ErrConnRefused {
			fmt.Println("found no server connection")
		} else {
			fmt.Println("unable to Dial jwtis server:", err.Error())
		}
		cli.Exit(1)
	}
}
