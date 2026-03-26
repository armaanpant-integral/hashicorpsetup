package vault

import (
	"fmt"
	"strings"
)

type mountRequest struct {
	Type    string            `json:"type"`
	Options map[string]string `json:"options,omitempty"`
}

func (c *Client) ensureKVV2Mount(token, mount string) error {
	mount = strings.Trim(mount, "/ ")
	if mount == "" {
		return fmt.Errorf("mount path is required")
	}

	err := c.doJSON("POST", fmt.Sprintf("/v1/sys/mounts/%s", mount), token, mountRequest{
		Type:    "kv",
		Options: map[string]string{"version": "2"},
	}, nil)
	if err == nil {
		return nil
	}
	// Treat "already mounted" as success for repeatable setup.
	if strings.Contains(err.Error(), "path is already in use") {
		return nil
	}
	return fmt.Errorf("ensure kv-v2 mount at %q: %w", mount, err)
}
