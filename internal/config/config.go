package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	VaultAddr      string
	TLSInsecure    bool
	TLSCACertPath  string
	ClientTimeoutS int
	LogLevel       string
	Retry          RetryConfig
	OIDC           OIDCConfig
	AppRole        AppRoleConfig
	Seal           SealConfig
}

type SealConfig struct {
	Type      string
	KMSKeyID  string
	KMSRegion string
}

type RetryConfig struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
}

type OIDCConfig struct {
	DiscoveryURL string
	ClientID     string
	ClientSecret string
	DefaultRole  string
	RedirectURIs []string
}

type AppRoleConfig struct {
	RoleName        string
	TokenPolicies   []string
	SecretIDTTL     string
	TokenTTL        string
	TokenMaxTTL     string
	SecretIDNumUses int
	BindSecretID    bool
}

func Load() Config {
	cfg := Config{
		VaultAddr:      getenvDefault("VAULT_ADDR", "http://127.0.0.1:18300"),
		TLSInsecure:    getenvBoolDefault("VAULT_TLS_INSECURE", false),
		TLSCACertPath:  os.Getenv("VAULT_CACERT"),
		ClientTimeoutS: getenvIntDefault("VAULT_CLIENT_TIMEOUT_S", 15),
		LogLevel:       getenvDefault("LOG_LEVEL", "info"),
		Retry: RetryConfig{
			MaxAttempts: getenvIntDefault("VAULT_RETRY_MAX_ATTEMPTS", 3),
			BaseDelay:   getenvDurationDefault("VAULT_RETRY_BASE_DELAY", 100*time.Millisecond),
			MaxDelay:    getenvDurationDefault("VAULT_RETRY_MAX_DELAY", 2*time.Second),
		},
		OIDC: OIDCConfig{
			DiscoveryURL: os.Getenv("VAULT_OIDC_DISCOVERY_URL"),
			ClientID:     os.Getenv("VAULT_OIDC_CLIENT_ID"),
			ClientSecret: os.Getenv("VAULT_OIDC_CLIENT_SECRET"),
			DefaultRole:  getenvDefault("VAULT_OIDC_DEFAULT_ROLE", "default"),
			RedirectURIs: splitCSV(os.Getenv("VAULT_OIDC_REDIRECT_URIS")),
		},
		AppRole: AppRoleConfig{
			RoleName:        getenvDefault("VAULT_APPROLE_NAME", "ci-cd"),
			TokenPolicies:   splitCSVDefault(os.Getenv("VAULT_APPROLE_POLICIES"), []string{"ci-cd"}),
			SecretIDTTL:     getenvDefault("VAULT_APPROLE_SECRET_ID_TTL", "10m"),
			TokenTTL:        getenvDefault("VAULT_APPROLE_TOKEN_TTL", "15m"),
			TokenMaxTTL:     getenvDefault("VAULT_APPROLE_TOKEN_MAX_TTL", "1h"),
			SecretIDNumUses: getenvIntDefault("VAULT_APPROLE_SECRET_ID_NUM_USES", 1),
			BindSecretID:    getenvBoolDefault("VAULT_APPROLE_BIND_SECRET_ID", true),
		},
		Seal: SealConfig{
			Type:      getenvDefault("VAULT_SEAL_TYPE", "shamir"),
			KMSKeyID:  os.Getenv("AWS_KMS_KEY_ID"),
			KMSRegion: os.Getenv("AWS_REGION"),
		},
	}
	return cfg
}

func (c Config) TLSConfig() (*tls.Config, error) {
	tc := &tls.Config{
		InsecureSkipVerify: c.TLSInsecure,
	}
	if c.TLSCACertPath != "" {
		pem, err := os.ReadFile(c.TLSCACertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert %s: %w", c.TLSCACertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no valid certs in %s", c.TLSCACertPath)
		}
		tc.RootCAs = pool
	}
	return tc, nil
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

func getenvDurationDefault(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func splitCSV(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	items := strings.Split(v, ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func splitCSVDefault(v string, def []string) []string {
	p := splitCSV(v)
	if len(p) == 0 {
		return def
	}
	return p
}
