package cmd

import (
	"os"
	"os/signal"
	"syscall"

	group "github.com/oklog/run"
	"go.uber.org/zap"
)

func initCancelInterrupt(logger *zap.Logger, cancelInterrupt chan struct{}, g *group.Group) {
	g.Add(func() error {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		select {
		case sig := <-c:
			// err := errors.Errorf("received signal %s", sig)
			logger.Info("cancel interrupt signal", zap.Any("signal", sig))
			return nil
		case <-cancelInterrupt:
			return nil
		}
	}, func(error) {
		close(cancelInterrupt)
	})
}
