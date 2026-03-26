package config

import (
	"crypto/tls"
	"os"
	"strconv"
)

type Config struct {
	VaultAddr      string
	TLSInsecure    bool
	TLSCACertPath  string
	ClientTimeoutS int
}

func Load() Config {
	cfg := Config{
		VaultAddr:      getenvDefault("VAULT_ADDR", "http://127.0.0.1:18300"),
		TLSInsecure:    getenvBoolDefault("VAULT_TLS_INSECURE", false),
		TLSCACertPath:  os.Getenv("VAULT_CACERT"),
		ClientTimeoutS: getenvIntDefault("VAULT_CLIENT_TIMEOUT_S", 15),
	}
	return cfg
}

func (c Config) TLSConfig() (*tls.Config, error) {
	// If we need to load a custom CA cert, the caller can do it. For now, keep it simple:
	// - Most local dev uses `tls_disable = 1`, so TLS settings don't matter.
	// - Provide `VAULT_TLS_INSECURE=1` as a convenience for self-signed certs.
	return &tls.Config{
		InsecureSkipVerify: c.TLSInsecure,
	}, nil
}

func getenvDefault(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func getenvBoolDefault(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func getenvIntDefault(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return i
}

