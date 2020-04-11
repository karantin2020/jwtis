package main

import (
	"os"

	"github.com/karantin2020/jwtis/cmd/cmd"
)

const (
	appName        = "jwtis"
	appDescription = "JWT issuer server. Provides trusted JWT tokens\n" +
		"\nSource https://github.com/karantin2020/jwtis"
	envPrefix  = "JWTIS_"
	bucketName = "jwtis"
)

var (
	app *cmd.Cli
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
