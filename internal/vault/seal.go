package vault

import (
	"fmt"
	"time"
)

type SealParams struct {
	Token string
}

func SealOperator(c *Client, p SealParams) error {
	if p.Token == "" {
		return fmt.Errorf("--token is required")
	}
	if err := c.Ping(2 * time.Second); err != nil {
		return err
	}
	// /v1/sys/seal uses PUT with X-Vault-Token header.
	return c.doJSON("PUT", "/v1/sys/seal", p.Token, nil, nil)
}

