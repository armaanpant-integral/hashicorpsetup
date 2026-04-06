package logger

import (
	"os"
	"strings"

	"github.com/rs/zerolog"
)

var Log = zerolog.New(os.Stdout).With().Timestamp().Str("service", "vault-operator").Logger()

func Init(level string) {
	if level == "" {
		level = "info"
	}
	parsed, err := zerolog.ParseLevel(strings.ToLower(level))
	if err != nil {
		parsed = zerolog.InfoLevel
	}
	Log = zerolog.New(os.Stdout).
		Level(parsed).
		With().
		Timestamp().
		Str("service", "vault-operator").
		Logger()
}
