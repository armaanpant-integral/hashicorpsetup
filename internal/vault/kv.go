package vault

import (
	"fmt"
	"strings"
)

type SealStatus struct {
	Sealed    bool `json:"sealed"`
	Threshold int  `json:"t"`
	Progress  int  `json:"progress"`
}

type kvGetResponse struct {
	Data struct {
		Data map[string]any `json:"data"`
	} `json:"data"`
}

type kvPutRequest struct {
	Data map[string]any `json:"data"`
}

func (c *Client) GetSealStatus() (*SealStatus, error) {
	var out SealStatus
	if err := c.doJSON("GET", "/v1/sys/seal-status", "", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) KVPut(token, path string, data map[string]any) error {
	mount, secretPath, err := parseSecretPath(path)
	if err != nil {
		return err
	}
	if token == "" {
		return fmt.Errorf("token is required")
	}
	if len(data) == 0 {
		return fmt.Errorf("data is required")
	}
	endpoint := fmt.Sprintf("/v1/%s/data/%s", mount, secretPath)
	err = c.doJSON("POST", endpoint, token, kvPutRequest{Data: data}, nil)
	if err == nil {
		return nil
	}
	if !strings.Contains(err.Error(), "no handler for route") {
		return err
	}
	if mountErr := c.ensureKVV2Mount(token, mount); mountErr != nil {
		return mountErr
	}
	return c.doJSON("POST", endpoint, token, kvPutRequest{Data: data}, nil)
}

func (c *Client) KVGet(token, path string) (map[string]any, error) {
	mount, secretPath, err := parseSecretPath(path)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, fmt.Errorf("token is required")
	}
	endpoint := fmt.Sprintf("/v1/%s/data/%s", mount, secretPath)
	var out kvGetResponse
	err = c.doJSON("GET", endpoint, token, nil, &out)
	if err == nil {
		return out.Data.Data, nil
	}
	if !strings.Contains(err.Error(), "no handler for route") {
		return nil, err
	}
	if mountErr := c.ensureKVV2Mount(token, mount); mountErr != nil {
		return nil, mountErr
	}
	var retry kvGetResponse
	if err := c.doJSON("GET", endpoint, token, nil, &retry); err != nil {
		return nil, err
	}
	return retry.Data.Data, nil
}

func parseSecretPath(path string) (mount string, secretPath string, err error) {
	clean := strings.Trim(path, "/ ")
	if clean == "" {
		return "", "", fmt.Errorf("secret path is required")
	}
	parts := strings.Split(clean, "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("secret path must include mount and key, e.g. secret/my-name")
	}
	mount = parts[0]
	secretPath = strings.Join(parts[1:], "/")
	if mount == "" || secretPath == "" {
		return "", "", fmt.Errorf("invalid secret path")
	}
	return mount, secretPath, nil
}
