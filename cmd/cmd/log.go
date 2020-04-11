package cmd

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

// LoggerConfig contains lumberjack options
type LoggerConfig struct {
	LogFileName  string `json:"LogFileName" yaml:"LogFileName"`   // file to write logs to
	LogMaxSize   int    `json:"LogMaxSize" yaml:"LogMaxSize"`     // megabytes
	LogMaxAge    int    `json:"LogMaxAge" yaml:"LogMaxAge"`       // maximum number of days to retain old log files
	LogMaxBackUp int    `json:"LogMaxBackUp" yaml:"LogMaxBackUp"` // maximum number of old log files to retain
	LogCompress  bool   `json:"LogCompress" yaml:"LogCompress"`   // determines if the rotated log files should be compressed
	LogLocalTime bool   `json:"LogLocalTime" yaml:"LogLocalTime"` // use local or UTC time in filename
	LogLevel     string `json:"LogLevel" yaml:"LogLevel"`         // priority is for config.Verbose
	LogFileSave  bool   `json:"LogFileSave" yaml:"LogFileSave"`
}

// newLogger constructs zap.Logger instance
func (r *rootCmd) newLogger() *zap.Logger {
	cfg := r.config.LoggerConfig
	writers := []zapcore.WriteSyncer{}
	if cfg.LogFileSave {
		if cfg.LogFileName == "" {
			cfg.LogFileName = "./data/jwtis.log"
		}
		writers = append(writers, zapcore.AddSync(&lumberjack.Logger{
			Filename:   cfg.LogFileName,
			MaxSize:    cfg.LogMaxSize,
			MaxAge:     cfg.LogMaxAge,
			MaxBackups: cfg.LogMaxBackUp,
			LocalTime:  cfg.LogLocalTime,
			Compress:   cfg.LogCompress,
		}))
	}
	writers = append(writers, os.Stderr)
	multiWriter := zapcore.NewMultiWriteSyncer(writers...)

	if *r.config.Verbose {
		cfg.LogLevel = "debug"
	}

	logLvl := func() zapcore.Level {
		switch cfg.LogLevel {
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

	return logger.With(zap.String("namespace", "jwtis"))
}
