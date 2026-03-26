package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"vault-operator/internal/gpg"
)

type InitParams struct {
	GPGKeysDir     string
	SecretShares  int
	SecretThreshold int
	OutDir         string
}

type InitResult struct {
	RootToken string
	ShardFiles []string
}

type initRequest struct {
	SecretShares    int `json:"secret_shares"`
	SecretThreshold int `json:"secret_threshold"`
}

type initResponse struct {
	KeysBase64 []string `json:"keys_base64"`
	RootToken  string   `json:"root_token"`
}

type gpgKey struct {
	index int
	path  string
}

func InitOperator(c *Client, p InitParams) (*InitResult, error) {
	if p.SecretShares <= 0 || p.SecretThreshold <= 0 {
		return nil, fmt.Errorf("secret_shares and secret_threshold must be > 0")
	}
	if p.SecretThreshold > p.SecretShares {
		return nil, fmt.Errorf("secret_threshold must be <= secret_shares")
	}
	if p.GPGKeysDir == "" {
		return nil, fmt.Errorf("--gpg-keys dir is required")
	}
	if p.OutDir == "" {
		p.OutDir = "."
	}

	members, err := discoverPublicKeys(p.GPGKeysDir)
	if err != nil {
		return nil, err
	}
	if len(members) < p.SecretShares {
		return nil, fmt.Errorf("need at least %d public keys, found %d in %q", p.SecretShares, len(members), p.GPGKeysDir)
	}
	members = members[:p.SecretShares]

	if err := c.Ping(2 * time.Second); err != nil {
		return nil, err
	}

	req := initRequest{
		SecretShares:    p.SecretShares,
		SecretThreshold: p.SecretThreshold,
	}
	var resp initResponse
	if err := c.doJSON("PUT", "/v1/sys/init", "", req, &resp); err != nil {
		return nil, err
	}
	if len(resp.KeysBase64) != p.SecretShares {
		return nil, fmt.Errorf("vault returned %d keys_base64, expected %d", len(resp.KeysBase64), p.SecretShares)
	}
	if resp.RootToken == "" {
		return nil, fmt.Errorf("vault returned empty root_token")
	}

	if err := os.MkdirAll(p.OutDir, 0o755); err != nil {
		return nil, fmt.Errorf("create out dir: %w", err)
	}

	shardFiles := make([]string, 0, p.SecretShares)
	for i := 0; i < p.SecretShares; i++ {
		keyShare := strings.TrimSpace(resp.KeysBase64[i])
		enc, err := gpg.EncryptString(keyShare, members[i].path)
		if err != nil {
			return nil, fmt.Errorf("encrypt shard %d for member public key %q: %w", i+1, members[i].path, err)
		}

		shardPath := filepath.Join(p.OutDir, fmt.Sprintf("shard-%d.gpg", i+1))
		if err := os.WriteFile(shardPath, enc, 0o600); err != nil {
			return nil, fmt.Errorf("write shard %q: %w", shardPath, err)
		}
		shardFiles = append(shardFiles, shardPath)
	}

	rootTokenPath := filepath.Join(p.OutDir, "root-token.txt")
	if err := os.WriteFile(rootTokenPath, []byte(resp.RootToken+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write root token: %w", err)
	}

	return &InitResult{RootToken: resp.RootToken, ShardFiles: shardFiles}, nil
}

func discoverPublicKeys(dir string) ([]gpgKey, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read gpg keys dir %q: %w", dir, err)
	}

	// Accept filenames like:
	// - member-1-public.asc
	// - member1-public.asc
	// - member-01-public.asc
	re := regexp.MustCompile(`(?i)member-?(\d+).*public.*\.(asc|pgp|gpg|key)$`)

	var keys []gpgKey
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		m := re.FindStringSubmatch(name)
		// m[0] is the full match, m[1] is the member index captured by (\d+)
		if len(m) != 3 {
			continue
		}
		idxStr := m[1]
		var idx int
		_, err := fmt.Sscanf(idxStr, "%d", &idx)
		if err != nil {
			return nil, fmt.Errorf("parse member index from %q: %w", name, err)
		}
		keys = append(keys, gpgKey{index: idx, path: filepath.Join(dir, name)})
	}

	sort.Slice(keys, func(i, j int) bool { return keys[i].index < keys[j].index })
	if len(keys) == 0 {
		return nil, fmt.Errorf("no public keys matching %q found in %q", re.String(), dir)
	}
	return keys, nil
}

