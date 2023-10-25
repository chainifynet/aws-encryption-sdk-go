// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"io"
	"os"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

var (
	log zerolog.Logger
)

func SetupGlobalLogger(level zerolog.Level, outputFormat OutputFormat) {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(level)
	//zerolog.SetGlobalLevel(zerolog.TraceLevel)

	var logWriter io.Writer
	switch outputFormat {
	case ConsoleOutput:
		logWriter = setupConsoleLogger()
		break
	case Default:
		logWriter = os.Stderr
		break
	default:
		logWriter = os.Stderr
		break
	}

	zlog.Logger = zlog.Output(logWriter).With().
		Caller().
		Logger().
		Level(level)
	log = zlog.Logger
}

func setupConsoleLogger() io.Writer {
	return zerolog.ConsoleWriter{
		Out:          os.Stdout,
		NoColor:      false,
		PartsExclude: []string{
			//"time",
			//"bytes",
		},
		//TimeFormat: time.StampNano,
		//FieldsExclude: []string{"bytes"},
		//PartsOrder:    []string{"time", "level", "caller", "message", "len", "cap"},
		FormatMessage: formatMessage,
		FormatLevel:   consoleFormatLevel(false),
	}
}

func init() {
	SetupGlobalLogger(LogLevel, LogOutput)
	//loggerInstance = zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	//zerolog.New(os.Stdout).With().Logger()

	//zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	//zerolog.SetGlobalLevel(zerolog.TraceLevel)

	//log.Logger = log.Output(zerolog.ConsoleWriter{
	//	Out: os.Stdout,
	//	PartsExclude: []string{
	//		"time",
	//		//"bytes",
	//	},
	//	FieldsExclude: []string{"bytes"},
	//	//PartsOrder:    []string{"time", "level", "caller", "message", "len", "cap"},
	//	FormatMessage: formatMessage,
	//	FormatLevel:   consoleFormatLevel(false),
	//}).With().
	//	//Caller().
	//	Logger()

	//log.Logger = log.With().Caller().Logger()

	//loggerInstance = log.Logger

	log.Info().
		Str("logLevel", log.GetLevel().String()).
		Str("logWriter", string(LogOutput)).
		Msg("Setup Global Logger")
}

func L() *zerolog.Logger {
	return &log
}
