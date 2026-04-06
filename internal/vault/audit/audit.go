package audit

import (
	"context"
	"fmt"
	"strings"

	"vault-operator/internal/vault"
)

type enableReq struct {
	Type    string            `json:"type"`
	Options map[string]string `json:"options,omitempty"`
}

func EnableFile(client *vault.Client, token, backendPath, logPath string) error {
	if backendPath == "" {
		backendPath = "file"
	}
	req := enableReq{
		Type:    "file",
		Options: map[string]string{"file_path": logPath, "mode": "0600"},
	}
	err := client.RequestJSON(context.Background(), "PUT", "/v1/sys/audit/"+strings.Trim(backendPath, "/"), token, req, nil)
	if err != nil && strings.Contains(err.Error(), "path is already in use") {
		return nil
	}
	if err != nil {
		return fmt.Errorf("enable file audit backend: %w", err)
	}
	return nil
}

func EnableSyslog(client *vault.Client, token, backendPath string) error {
	if backendPath == "" {
		backendPath = "syslog"
	}
	req := enableReq{Type: "syslog"}
	err := client.RequestJSON(context.Background(), "PUT", "/v1/sys/audit/"+strings.Trim(backendPath, "/"), token, req, nil)
	if err != nil && strings.Contains(err.Error(), "path is already in use") {
		return nil
	}
	if err != nil {
		return fmt.Errorf("enable syslog audit backend: %w", err)
	}
	return nil
}
