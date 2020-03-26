package main

import (
	"os"

	"github.com/karantin2020/jwtis/cmdz/cmd"
)

const (
	appName        = "jwtis"
	appDescription = "JWT issuer server. Provides trusted JWT tokens\n" +
		"\nSource https://github.com/karantin2020/jwtis"
	envPrefix  = "JWTIS_"
	bucketName = "jwtis"
	// passwordLength = 32
)

var (
	// appVersion = "v0.3.1"
	// boltDB     *bolt.DB
	// buckets    = map[string][]byte{
	// 	"internalBucketName": []byte("internalBucket"),
	// 	"keysBucketName":     []byte("keysBucket"),
	// }
	app *cmd.Cli
	// confRepo      configRepository
	// internalsRepo internalRepository
	// keysRepo      jwtis.KeysRepository
	// log           zerolog.Logger
)

func main() {
	app := cmd.App(appName, appDescription)
	app.Config(bucketName, envPrefix)
	app.Version("V version", cmd.BuildDetails())
	// app.Command("version", "get version details", func(cmd *cli.Cmd) {
	// 	cmd.Action = func() {
	// 		fmt.Printf("user %q details (detailed mode: %v)\n", *id, *detailed)
	// 	}
	// })
	app.Run(os.Args)
}
