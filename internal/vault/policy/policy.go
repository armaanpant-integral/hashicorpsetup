package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"vault-operator/internal/vault"
)

type applyReq struct {
	Policy string `json:"policy"`
}

func ApplyFromDir(client *vault.Client, token, dir string) ([]string, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("policy directory is required")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read policy dir: %w", err)
	}
	applied := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".hcl") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".hcl")
		p := filepath.Join(dir, entry.Name())
		content, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read policy file %s: %w", p, err)
		}
		if err := client.RequestJSON(context.Background(), "PUT", "/v1/sys/policies/acl/"+name, token, applyReq{Policy: string(content)}, nil); err != nil {
			return nil, fmt.Errorf("apply policy %s: %w", name, err)
		}
		applied = append(applied, name)
	}
	sort.Strings(applied)
	return applied, nil
}
