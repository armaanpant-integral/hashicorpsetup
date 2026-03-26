package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"vault-operator/internal/config"
	"vault-operator/internal/vault"

	"github.com/spf13/cobra"
)

func main() {
	baseCfg := config.Load()

	var (
		vaultAddr      = baseCfg.VaultAddr
		tlsInsecure    = baseCfg.TLSInsecure
		clientTimeoutS = baseCfg.ClientTimeoutS
	)

	var rootCmd = &cobra.Command{
		Use:   "vault-operator",
		Short: "Local helper for initializing/unsealing/sealing Vault with GPG-encrypted shards.",
	}

	rootCmd.PersistentFlags().StringVar(&vaultAddr, "vault-addr", vaultAddr, "Vault address (env: VAULT_ADDR)")
	rootCmd.PersistentFlags().BoolVar(&tlsInsecure, "vault-tls-insecure", tlsInsecure, "Skip TLS verification (env: VAULT_TLS_INSECURE)")
	rootCmd.PersistentFlags().IntVar(&clientTimeoutS, "vault-client-timeout-s", clientTimeoutS, "HTTP client timeout in seconds")

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize Vault and write member-encrypted unseal shards.",
		RunE: func(cmd *cobra.Command, args []string) error {
			gpgKeysDir, _ := cmd.Flags().GetString("gpg-keys")
			outDir, _ := cmd.Flags().GetString("out-dir")
			shares, _ := cmd.Flags().GetInt("secret-shares")
			threshold, _ := cmd.Flags().GetInt("secret-threshold")

			cfg := config.Config{
				VaultAddr:      vaultAddr,
				TLSInsecure:    tlsInsecure,
				TLSCACertPath:  baseCfg.TLSCACertPath,
				ClientTimeoutS: clientTimeoutS,
			}

			client, err := vault.New(cfg)
			if err != nil {
				return err
			}
			res, err := vault.InitOperator(client, vault.InitParams{
				GPGKeysDir:      gpgKeysDir,
				SecretShares:    shares,
				SecretThreshold: threshold,
				OutDir:          outDir,
			})
			if err != nil {
				return err
			}

			fmt.Printf("Vault initialized.\nRoot token written to %s/root-token.txt\n", outDir)
			fmt.Println("Shard files:")
			for _, f := range res.ShardFiles {
				fmt.Printf("  %s\n", f)
			}
			return nil
		},
	}
	initCmd.Flags().String("gpg-keys", "", "Directory containing member public keys (member-1-public.asc, ...)")
	_ = initCmd.MarkFlagRequired("gpg-keys")
	initCmd.Flags().String("out-dir", ".", "Output directory for shard-*.gpg and root-token.txt")
	initCmd.Flags().Int("secret-shares", 10, "Total number of unseal key shards")
	initCmd.Flags().Int("secret-threshold", 5, "Number of shards required to unseal")

	unsealCmd := &cobra.Command{
		Use:   "unseal",
		Short: "Decrypt one shard with the member private key and unseal Vault.",
		RunE: func(cmd *cobra.Command, args []string) error {
			shardPath, _ := cmd.Flags().GetString("shard")
			privateKeyPath, _ := cmd.Flags().GetString("private-key")
			passphrase, _ := cmd.Flags().GetString("passphrase")

			if passphrase == "" {
				passphrase = os.Getenv("GPG_PASSPHRASE")
			}

			cfg := config.Config{
				VaultAddr:      vaultAddr,
				TLSInsecure:    tlsInsecure,
				TLSCACertPath:  baseCfg.TLSCACertPath,
				ClientTimeoutS: clientTimeoutS,
			}

			client, err := vault.New(cfg)
			if err != nil {
				return err
			}

			res, err := vault.UnsealOperator(client, vault.UnsealParams{
				ShardPath:      shardPath,
				PrivateKeyPath: privateKeyPath,
				Passphrase:     passphrase,
			})
			if err != nil {
				return err
			}

			if res.Sealed {
				fmt.Printf("Vault still sealed. Progress: %d/%d\n", res.Progress, res.Threshold)
			} else {
				fmt.Println("Vault unsealed successfully.")
			}
			return nil
		},
	}
	unsealCmd.Flags().String("shard", "", "Path to shard-*.gpg file")
	_ = unsealCmd.MarkFlagRequired("shard")
	unsealCmd.Flags().String("private-key", "", "Path to the member private key (member-*-private.asc)")
	_ = unsealCmd.MarkFlagRequired("private-key")
	unsealCmd.Flags().String("passphrase", "", "Private key passphrase (or env GPG_PASSPHRASE if omitted)")

	sealCmd := &cobra.Command{
		Use:   "seal",
		Short: "Seal Vault using a root token.",
		RunE: func(cmd *cobra.Command, args []string) error {
			token, _ := cmd.Flags().GetString("token")
			if token == "" {
				token = os.Getenv("VAULT_TOKEN")
			}
			client, err := vault.New(config.Config{
				VaultAddr:      vaultAddr,
				TLSInsecure:    tlsInsecure,
				TLSCACertPath:  baseCfg.TLSCACertPath,
				ClientTimeoutS: clientTimeoutS,
			})
			if err != nil {
				return err
			}

			if err := vault.SealOperator(client, vault.SealParams{Token: token}); err != nil {
				return err
			}

			fmt.Println("Vault sealed.")
			return nil
		},
	}
	sealCmd.Flags().String("token", "", "Root token (or env VAULT_TOKEN if omitted)")

	uiCmd := &cobra.Command{
		Use:   "ui",
		Short: "Start a simple local web UI to read/write Vault secrets.",
		RunE: func(cmd *cobra.Command, args []string) error {
			listenAddr, _ := cmd.Flags().GetString("listen-addr")

			client, err := vault.New(config.Config{
				VaultAddr:      vaultAddr,
				TLSInsecure:    tlsInsecure,
				TLSCACertPath:  baseCfg.TLSCACertPath,
				ClientTimeoutS: clientTimeoutS,
			})
			if err != nil {
				return err
			}

			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write([]byte(uiHTML))
			})
			mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				status, err := client.GetSealStatus()
				if err != nil {
					writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
					return
				}
				writeJSON(w, http.StatusOK, status)
			})
			mux.HandleFunc("/api/secret/write", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				var in struct {
					Token string `json:"token"`
					Path  string `json:"path"`
					Key   string `json:"key"`
					Value string `json:"value"`
				}
				if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
					writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
					return
				}
				if in.Key == "" {
					writeJSON(w, http.StatusBadRequest, map[string]any{"error": "key is required"})
					return
				}
				if err := client.KVPut(in.Token, in.Path, map[string]any{in.Key: in.Value}); err != nil {
					writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
					return
				}
				writeJSON(w, http.StatusOK, map[string]any{"ok": true})
			})
			mux.HandleFunc("/api/secret/read", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				var in struct {
					Token string `json:"token"`
					Path  string `json:"path"`
				}
				if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
					writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
					return
				}
				data, err := client.KVGet(in.Token, in.Path)
				if err != nil {
					writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
					return
				}
				writeJSON(w, http.StatusOK, map[string]any{"data": data})
			})

			srv := &http.Server{
				Addr:              listenAddr,
				Handler:           mux,
				ReadHeaderTimeout: 3 * time.Second,
			}
			fmt.Printf("UI running at http://127.0.0.1%s\n", listenAddr)
			return srv.ListenAndServe()
		},
	}
	uiCmd.Flags().String("listen-addr", ":8080", "Local address for UI server")

	rootCmd.AddCommand(initCmd, unsealCmd, sealCmd, uiCmd)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

const uiHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Vault Operator UI</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; background: #f6f8fa; color: #111; }
    .card { max-width: 850px; background: #fff; border: 1px solid #d0d7de; border-radius: 10px; padding: 16px; margin-bottom: 14px; }
    h2 { margin-top: 0; }
    label { display: block; margin-top: 10px; font-weight: 600; }
    input { width: 100%; padding: 8px; margin-top: 6px; box-sizing: border-box; border: 1px solid #d0d7de; border-radius: 6px; }
    button { margin-top: 12px; padding: 8px 14px; border: 0; border-radius: 6px; cursor: pointer; background: #0969da; color: #fff; }
    button.secondary { background: #57606a; }
    pre { background: #0d1117; color: #e6edf3; padding: 10px; border-radius: 8px; overflow-x: auto; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Vault Unseal / Secret UI</h2>
    <p>1) Unseal Vault with CLI first.<br>2) Put token and path.<br>3) Click <b>Enter</b> to fetch and show secrets.</p>
    <button class="secondary" onclick="checkStatus()">Check Vault Status</button>
    <pre id="statusOut">Status will appear here...</pre>
  </div>

  <div class="card">
    <h2>Create Secret (example: your name)</h2>
    <label>Vault Token</label>
    <input id="token" placeholder="s.xxxxx" />
    <label>Secret Path</label>
    <input id="path" value="secret/my-name" />
    <label>Field Key</label>
    <input id="fieldKey" value="name" />
    <label>Field Value</label>
    <input id="fieldValue" placeholder="xyz" />
    <button onclick="saveSecret()">Save Secret</button>
    <pre id="writeOut">Write result...</pre>
  </div>

  <div class="card">
    <h2>Enter (Fetch Secret)</h2>
    <label>Vault Token</label>
    <input id="tokenRead" placeholder="s.xxxxx" />
    <label>Secret Path</label>
    <input id="pathRead" value="secret/my-name" />
    <button onclick="enterFetch()">Enter</button>
    <pre id="readOut">Fetched secret will appear here...</pre>
  </div>

  <script>
    function pretty(obj) {
      return JSON.stringify(obj, null, 2);
    }
    async function checkStatus() {
      const out = document.getElementById('statusOut');
      const res = await fetch('/api/status');
      const data = await res.json();
      out.textContent = pretty(data);
    }
    async function saveSecret() {
      const out = document.getElementById('writeOut');
      const token = document.getElementById('token').value;
      const path = document.getElementById('path').value;
      const key = document.getElementById('fieldKey').value;
      const value = document.getElementById('fieldValue').value;
      const res = await fetch('/api/secret/write', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ token, path, key, value })
      });
      const data = await res.json();
      out.textContent = pretty(data);
    }
    async function enterFetch() {
      const out = document.getElementById('readOut');
      const token = document.getElementById('tokenRead').value || document.getElementById('token').value;
      const path = document.getElementById('pathRead').value;
      const res = await fetch('/api/secret/read', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ token, path })
      });
      const data = await res.json();
      out.textContent = pretty(data);
    }
  </script>
</body>
</html>`
