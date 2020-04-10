package cmd

import (
	"fmt"
	"os"
	"strings"

	cli "github.com/jawher/mow.cli"
	"github.com/segmentio/encoding/json"
	"gopkg.in/yaml.v3"
)

func (r *rootCmd) printConfigCMD(app *cli.Cli) {
	app.Command("p printConfig", "print default config files", func(cmd *cli.Cmd) {
		var (
			basePath = "./config/"
			ymlPath  = "config.yml"
			jsonPath = "config.json"
		)
		var (
			dir = cmd.StringOpt("d dir", basePath, "string Directory to store config files")
		)

		cmd.Action = func() {
			if *dir != "." && *dir != "./" {
				if _, err := os.Stat(*dir); os.IsNotExist(err) {
					os.Mkdir(*dir, 0644)
				}
			}
			if strings.HasSuffix(*dir, "/") {
				*dir = *dir + "/"
			}
			ymlBin, err := yaml.Marshal(r.config)
			os.Remove(*dir + ymlPath)
			f, err := os.OpenFile(*dir+ymlPath, os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error open yml config file")
				cli.Exit(1)
			}
			if _, err = f.Write(ymlBin); err != nil {
				f.Close() // ignore error; Write error takes precedence
				fmt.Fprintf(os.Stderr, "error write yml config file")
				cli.Exit(1)
			}
			if err := f.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "error close yml config file after write")
				cli.Exit(1)
			}

			jsonBin, err := json.MarshalIndent(r.config, "", "  ")
			os.Remove(*dir + jsonPath)
			f, err = os.OpenFile(*dir+jsonPath, os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error write json config file")
				cli.Exit(1)
			}
			if _, err = f.Write(jsonBin); err != nil {
				f.Close() // ignore error; Write error takes precedence
				fmt.Fprintf(os.Stderr, "error write json config file")
				cli.Exit(1)
			}
			if err := f.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "error close json config file after write")
				cli.Exit(1)
			}
		}
	})
}
