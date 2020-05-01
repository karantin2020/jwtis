package main

import (
	"fmt"
	"os"

	client "github.com/karantin2020/jwtis/cmd/client/pkg/client"
	log "github.com/karantin2020/jwtis/cmd/client/pkg/log"
	"go.uber.org/zap"
)

var grpcHostAndPort = "127.0.0.1:40430"

func main() {
	logger := log.New("info")
	defer logger.Sync()

	cl, err := client.New(grpcHostAndPort)
	if err != nil {
		logger.Info("unable to Dial", zap.Error(err))
		os.Exit(1)
	}
	v, err := cl.Version()
	if err != nil {
		logger.Info("unable to fetch version", zap.Error(err))
		os.Exit(1)
	}
	fmt.Printf(`
Version: %v
Checksum: %x
LastCommitSHA: %v
LastCommitTime: %v
BuildTime: %v
GitBranch: %v
GoVersion: %v

`, v.Version, v.Checksum, v.LastCommitSHA, v.LastCommitTime, v.BuildTime, v.GitBranch, v.GoVersion)
}
