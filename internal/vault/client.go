package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"vault-operator/internal/config"
	"vault-operator/internal/logger"

	"github.com/google/uuid"
)

type Client struct {
	addr     string
	http     *http.Client
	tlsInsec bool
	retry    config.RetryConfig
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
		addr:     strings.TrimRight(cfg.VaultAddr, "/"),
		http:     &http.Client{Timeout: time.Duration(cfg.ClientTimeoutS) * time.Second, Transport: transport},
		tlsInsec: cfg.TLSInsecure,
		retry:    cfg.Retry,
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
	return c.doJSONWithRetry(context.Background(), method, path, reqBody, out, token)
}

// RequestJSON is used by subpackages (auth/policy/audit) for Vault API calls.
func (c *Client) RequestJSON(ctx context.Context, method, path, token string, reqBody, out any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	return c.doJSONWithRetry(ctx, method, path, reqBody, out, token)
}

func (c *Client) doJSONWithRetry(ctx context.Context, method, path string, body, out any, token string) error {
	maxAttempts := c.retry.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 1
	}
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			delay := c.backoffDelay(attempt)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return fmt.Errorf("vault request canceled: %w", ctx.Err())
			}
		}
		rid := newRequestID()
		err := c.doJSONOnce(ctx, method, path, token, rid, body, out)
		if err == nil {
			return nil
		}
		if !isRetryable(err) {
			return err
		}
		logger.Log.Warn().
			Str("component", "vault/client").
			Str("request_id", rid).
			Int("attempt", attempt+1).
			Err(err).
			Msg("retrying vault request")
		lastErr = err
	}
	return fmt.Errorf("vault request failed after %d attempts: %w", maxAttempts, lastErr)
}

func (c *Client) doJSONOnce(ctx context.Context, method, path string, token, requestID string, reqBody any, out any) error {
	var bodyReader io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.addr+path, bodyReader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	req.Header.Set("X-Request-ID", requestID)

	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request %s %s: %w", method, path, c.hintConnErr(err))
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	logger.Log.Info().
		Str("component", "vault/client").
		Str("request_id", requestID).
		Str("method", method).
		Str("path", path).
		Int("status_code", resp.StatusCode).
		Int64("duration_ms", time.Since(start).Milliseconds()).
		Msg("vault api call")

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

func (c *Client) backoffDelay(attempt int) time.Duration {
	base := c.retry.BaseDelay
	if base <= 0 {
		base = 100 * time.Millisecond
	}
	maxDelay := c.retry.MaxDelay
	if maxDelay <= 0 {
		maxDelay = 2 * time.Second
	}
	delay := base * time.Duration(1<<attempt)
	if delay > maxDelay {
		delay = maxDelay
	}
	jitterSpan := int64(delay / 5)
	if jitterSpan <= 0 {
		return delay
	}
	// +/-20% jitter.
	jitter := rand.Int63n(jitterSpan*2) - jitterSpan
	return delay + time.Duration(jitter)
}

func newRequestID() string {
	return uuid.NewString()
}

func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "status=429") || strings.Contains(msg, "status=503") {
		return true
	}
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "timeout") {
		return true
	}
	return false
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
