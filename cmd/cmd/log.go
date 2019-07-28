package cmd

import (
	"io"
	"os"

	"github.com/rs/zerolog"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

func logger(path string) zerolog.Logger {
	if path == "" {
		path = "./data/jwtis.log"
	}
	zerolog.TimestampFieldName = "t"
	zerolog.LevelFieldName = "l"
	zerolog.MessageFieldName = "m"
	log := zerolog.New(io.MultiWriter(&lumberjack.Logger{
		Filename:   path,
		MaxSize:    15, // megabytes
		MaxBackups: 3,
		MaxAge:     28,   //days
		Compress:   true, // disabled by default
	},
		os.Stderr,
	)).With().
		Timestamp().
		Str("service", "jwtis").
		Logger()
	return log
}
