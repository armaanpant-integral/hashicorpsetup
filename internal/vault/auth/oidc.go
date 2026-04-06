package auth

import (
	"context"
	"fmt"
	"strings"

	"vault-operator/internal/logger"
	"vault-operator/internal/vault"
)

type OIDCParams struct {
	DiscoveryURL string
	ClientID     string
	ClientSecret string
	DefaultRole  string
	Roles        []OIDCRole
	GroupMapping map[string]string
}

type OIDCRole struct {
	Name                string
	BoundAudiences      []string
	AllowedRedirectURIs []string
	UserClaim           string
	GroupsClaim         string
	TokenPolicies       []string
	TokenTTL            string
	TokenMaxTTL         string
}

func SetupOIDC(client *vault.Client, token string, p OIDCParams) error {
	ctx := context.Background()
	if err := enableOIDC(ctx, client, token); err != nil {
		return err
	}
	if err := configureOIDC(ctx, client, token, p); err != nil {
		return err
	}
	for _, role := range p.Roles {
		if err := createOIDCRole(ctx, client, token, role); err != nil {
			return err
		}
	}
	if len(p.GroupMapping) > 0 {
		accessor, err := lookupMountAccessor(ctx, client, token, "oidc/")
		if err != nil {
			return err
		}
		for idpGroup, policyName := range p.GroupMapping {
			if err := createExternalGroup(ctx, client, token, accessor, idpGroup, policyName); err != nil {
				return err
			}
		}
	}
	return nil
}

func enableOIDC(ctx context.Context, client *vault.Client, token string) error {
	err := client.RequestJSON(ctx, "POST", "/v1/sys/auth/oidc", token, map[string]any{
		"type": "oidc",
	}, nil)
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		return fmt.Errorf("enable oidc auth method: %w", err)
	}
	return nil
}

func configureOIDC(ctx context.Context, client *vault.Client, token string, p OIDCParams) error {
	req := map[string]any{
		"oidc_discovery_url": p.DiscoveryURL,
		"oidc_client_id":     p.ClientID,
		"oidc_client_secret": p.ClientSecret,
		"default_role":       p.DefaultRole,
	}
	if err := client.RequestJSON(ctx, "POST", "/v1/auth/oidc/config", token, req, nil); err != nil {
		return fmt.Errorf("configure oidc auth method: %w", err)
	}
	return nil
}

func createOIDCRole(ctx context.Context, client *vault.Client, token string, role OIDCRole) error {
	req := map[string]any{
		"bound_audiences":       role.BoundAudiences,
		"allowed_redirect_uris": role.AllowedRedirectURIs,
		"user_claim":            role.UserClaim,
		"groups_claim":          role.GroupsClaim,
		"token_policies":        role.TokenPolicies,
		"token_ttl":             role.TokenTTL,
		"token_max_ttl":         role.TokenMaxTTL,
	}
	path := "/v1/auth/oidc/role/" + role.Name
	if err := client.RequestJSON(ctx, "POST", path, token, req, nil); err != nil {
		return fmt.Errorf("create oidc role %s: %w", role.Name, err)
	}
	return nil
}

func lookupMountAccessor(ctx context.Context, client *vault.Client, token, mount string) (string, error) {
	var out map[string]struct {
		Accessor string `json:"accessor"`
	}
	if err := client.RequestJSON(ctx, "GET", "/v1/sys/auth", token, nil, &out); err != nil {
		return "", fmt.Errorf("read auth mounts: %w", err)
	}
	m, ok := out[mount]
	if !ok || m.Accessor == "" {
		return "", fmt.Errorf("auth mount %q accessor not found", mount)
	}
	return m.Accessor, nil
}

func createExternalGroup(ctx context.Context, client *vault.Client, token, mountAccessor, idpGroup, policyName string) error {
	var createResp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := client.RequestJSON(ctx, "POST", "/v1/identity/group", token, map[string]any{
		"name":                       idpGroup,
		"type":                       "external",
		"policies":                   []string{policyName},
		"metadata":                   map[string]string{"source": "oidc"},
		"external_member_entity_ids": []string{},
	}, &createResp); err != nil {
		if strings.Contains(err.Error(), "existing group") {
			logger.Log.Info().Str("component", "vault/auth/oidc").Str("group", idpGroup).Msg("external group already exists")
			return nil
		}
		return fmt.Errorf("create external identity group %s: %w", idpGroup, err)
	}
	if createResp.Data.ID == "" {
		return fmt.Errorf("external group %s created without id", idpGroup)
	}
	err := client.RequestJSON(ctx, "POST", "/v1/identity/group-alias", token, map[string]any{
		"name":           idpGroup,
		"mount_accessor": mountAccessor,
		"canonical_id":   createResp.Data.ID,
	}, nil)
	if err != nil && !strings.Contains(err.Error(), "existing alias") {
		return fmt.Errorf("create group alias %s: %w", idpGroup, err)
	}
	return nil
}
