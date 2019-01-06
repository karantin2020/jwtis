package main

import (
	cli "github.com/jawher/mow.cli"
)

type cmdConf struct {
	path   string
	desc   string
	config func(*cli.Cmd)
}

var cmds = []cmdConf{}

func addCommands(topcli *cli.Cli, confs []cmdConf) {
	for i := range confs {
		topcli.Command(confs[i].path, confs[i].desc, confs[i].config)
	}
}
