package main

import (
	"os"

	"github.com/karantin2020/jwtis/client/cmd"
	log "github.com/karantin2020/jwtis/client/pkg/log"
)

var grpcHostAndPort = "127.0.0.1:40430"

func main() {
	logger := log.New("info")
	defer logger.Sync()

	cli := cmd.Cmd(logger)
	cli.Run(os.Args)
}
