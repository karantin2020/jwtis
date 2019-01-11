package main

import (
	"io"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

func logger(path string) zerolog.Logger {
	if path == "" {
		dir, _ := filepath.Split(*confRepo.dbPath)
		path = filepath.Join(dir, "jwtis.log")
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
		Str("source", "jwtis").
		Logger()
	return log
}
