package auth

import (
	"context"
	"fmt"
	"strings"

	"vault-operator/internal/vault"
)

type AppRoleParams struct {
	RoleName        string
	TokenPolicies   []string
	SecretIDTTL     string
	TokenTTL        string
	TokenMaxTTL     string
	BindSecretID    bool
	SecretIDNumUses int
}

func SetupAppRole(client *vault.Client, token string, p AppRoleParams) error {
	ctx := context.Background()
	if err := enableAppRole(ctx, client, token); err != nil {
		return err
	}
	if err := createRole(ctx, client, token, p); err != nil {
		return err
	}
	return nil
}

func enableAppRole(ctx context.Context, client *vault.Client, token string) error {
	err := client.RequestJSON(ctx, "POST", "/v1/sys/auth/approle", token, map[string]any{
		"type": "approle",
	}, nil)
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		return fmt.Errorf("enable approle auth method: %w", err)
	}
	return nil
}

func createRole(ctx context.Context, client *vault.Client, token string, p AppRoleParams) error {
	if p.RoleName == "" {
		p.RoleName = "ci-cd"
	}
	req := map[string]any{
		"token_policies":     p.TokenPolicies,
		"secret_id_ttl":      p.SecretIDTTL,
		"token_ttl":          p.TokenTTL,
		"token_max_ttl":      p.TokenMaxTTL,
		"bind_secret_id":     p.BindSecretID,
		"secret_id_num_uses": p.SecretIDNumUses,
	}
	if err := client.RequestJSON(ctx, "POST", "/v1/auth/approle/role/"+p.RoleName, token, req, nil); err != nil {
		return fmt.Errorf("configure approle %s: %w", p.RoleName, err)
	}
	return nil
}
