package log

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New returns configured zap logger
func New(lvl string) *zap.Logger {
	writers := []zapcore.WriteSyncer{os.Stderr}
	multiWriter := zapcore.NewMultiWriteSyncer(writers...)

	logLvl := func() zapcore.Level {
		switch lvl {
		case "debug":
			return zapcore.DebugLevel
		case "info":
			return zapcore.InfoLevel
		case "warn":
			return zapcore.WarnLevel
		case "error":
			return zapcore.ErrorLevel
		default:
			return zapcore.InfoLevel
		}
	}()

	zapCfg := zap.NewProductionEncoderConfig()
	zapCfg.EncodeTime = zapcore.RFC3339NanoTimeEncoder

	core := zapcore.NewCore(zapcore.NewJSONEncoder(zapCfg), multiWriter, logLvl)
	logger := zap.New(core)

	return logger.With(zap.String("namespace", "jwtis-client"))
}
