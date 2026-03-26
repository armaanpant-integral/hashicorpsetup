package vault

import (
	"fmt"
	"strings"
	"time"

	"vault-operator/internal/gpg"
)

type UnsealParams struct {
	ShardPath     string
	PrivateKeyPath string
	Passphrase    string
}

type UnsealResult struct {
	Sealed   bool
	Progress int
	Threshold int
	N         int
}

type unsealRequest struct {
	Key string `json:"key"`
}

type unsealResponse struct {
	Sealed    bool   `json:"sealed"`
	T         int    `json:"t"`
	N         int    `json:"n"`
	Progress  int    `json:"progress"`
}

func UnsealOperator(c *Client, p UnsealParams) (*UnsealResult, error) {
	if p.ShardPath == "" {
		return nil, fmt.Errorf("shard path is required")
	}
	if p.PrivateKeyPath == "" {
		return nil, fmt.Errorf("private key path is required (--private-key)")
	}

	keyShareB64, err := gpg.DecryptString(p.ShardPath, p.PrivateKeyPath, p.Passphrase)
	if err != nil {
		return nil, err
	}
	keyShareB64 = strings.TrimSpace(keyShareB64)
	if keyShareB64 == "" {
		return nil, fmt.Errorf("decrypted shard yielded an empty key")
	}

	if err := c.Ping(2 * time.Second); err != nil {
		return nil, err
	}

	var resp unsealResponse
	if err := c.doJSON("PUT", "/v1/sys/unseal", "", unsealRequest{Key: keyShareB64}, &resp); err != nil {
		return nil, err
	}
	return &UnsealResult{
		Sealed: resp.Sealed,
		Progress: resp.Progress,
		Threshold: resp.T,
		N: resp.N,
	}, nil
}

