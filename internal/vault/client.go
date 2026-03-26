package vault

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"vault-operator/internal/config"
)

type Client struct {
	addr    string
	http    *http.Client
	tlsInsec bool
}

func New(cfg config.Config) (*Client, error) {
	tlsCfg, err := cfg.TLSConfig()
	if err != nil {
		return nil, fmt.Errorf("tls config: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
	}

	return &Client{
		addr:    strings.TrimRight(cfg.VaultAddr, "/"),
		http:    &http.Client{Timeout: time.Duration(cfg.ClientTimeoutS) * time.Second, Transport: transport},
		tlsInsec: cfg.TLSInsecure,
	}, nil
}

func (c *Client) Ping(timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	u, err := url.Parse(c.addr)
	if err != nil {
		return fmt.Errorf("parse vault addr %q: %w", c.addr, err)
	}

	host := u.Host
	if host == "" {
		return fmt.Errorf("invalid vault addr %q (missing host)", c.addr)
	}
	if _, _, splitErr := net.SplitHostPort(host); splitErr != nil {
		// No explicit port; infer from scheme.
		switch strings.ToLower(u.Scheme) {
		case "https":
			host = net.JoinHostPort(host, "443")
		default:
			host = net.JoinHostPort(host, "80")
		}
	}

	conn, err := net.DialTimeout("tcp", host, timeout)
	if err != nil {
		return c.hintConnErr(err)
	}
	_ = conn.Close()
	return nil
}

func (c *Client) doJSON(method, path string, token string, reqBody any, out any) error {
	var bodyReader io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, c.addr+path, bodyReader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request %s %s: %w", method, path, c.hintConnErr(err))
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 300 {
		// Vault often returns a JSON error object; include raw body for debugging.
		return fmt.Errorf("vault %s %s failed: status=%d body=%s", method, path, resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}

	if out == nil || len(respBytes) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBytes, out); err != nil {
		return fmt.Errorf("unmarshal response: %w (body=%s)", err, strings.TrimSpace(string(respBytes)))
	}
	return nil
}

func (c *Client) hintConnErr(err error) error {
	// Provide a high-signal hint for the most common local failure mode:
	// Vault isn't running / port not open.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.ECONNREFUSED) {
			return fmt.Errorf("%w (Vault not reachable at %s; tip: start it with `docker compose up -d` or set --vault-addr / VAULT_ADDR)", err, c.addr)
		}
	}

	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) && errors.Is(sysErr.Err, syscall.ECONNREFUSED) {
		return fmt.Errorf("%w (Vault not reachable at %s; tip: start it with `docker compose up -d` or set --vault-addr / VAULT_ADDR)", err, c.addr)
	}

	var uerr *url.Error
	if errors.As(err, &uerr) {
		if errors.Is(uerr.Err, syscall.ECONNREFUSED) {
			return fmt.Errorf("%w (Vault not reachable at %s; tip: start it with `docker compose up -d` or set --vault-addr / VAULT_ADDR)", err, c.addr)
		}
	}

	return err
}

// TLSInsecure is a convenience accessor for future CLI/UI work.
func (c *Client) TLSInsecure() bool { return c.tlsInsec }

// tlsConfig exists only to appease any future expansions.
func (c *Client) tlsConfig() (*tls.Config, bool) { return nil, c.tlsInsec }

