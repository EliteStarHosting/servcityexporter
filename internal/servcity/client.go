// Package servcity is a thin client for the ServCity User API
// (https://servcity.org/uapi/docs). It covers the read-only endpoints an
// exporter needs: account limits, DDoS config/metrics/attacks/firewall,
// tunnels, and Minecraft proxies.
package servcity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to the ServCity User API over HTTP Basic auth.
//
// The upstream OpenAPI spec declares its "apiKey" security scheme as
// `type: basic`, which is unusual for what's conceptually an API key. This
// client sends the key as the Basic-auth username with an empty password.
// That has not been confirmed against a live ServCity account — if
// authentication fails with a 401 on every request, try swapping to
// SetBasicAuth("", apiKey) here first before assuming the key itself is
// wrong.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewClient builds a Client. baseURL should not include a trailing slash
// (e.g. "https://servcity.org/uapi").
func NewClient(baseURL, apiKey string, timeout time.Duration) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

func (c *Client) get(ctx context.Context, path string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("build request for %s: %w", path, err)
	}
	req.SetBasicAuth(c.apiKey, "")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return fmt.Errorf("read response for GET %s: %w", path, err)
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return &AuthError{Path: path, StatusCode: resp.StatusCode, Body: string(data)}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{Path: path, StatusCode: resp.StatusCode, Body: string(data)}
	}

	if out == nil {
		return nil
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode response for GET %s: %w (body: %s)", path, err, truncate(string(data), 500))
	}
	return nil
}

// esc URL-escapes a single path segment (IP addresses, tunnel/proxy IDs).
func esc(s string) string {
	return url.PathEscape(s)
}

// GetAccountLimits calls GET /user/limits.
func (c *Client) GetAccountLimits(ctx context.Context) (*AccountLimits, error) {
	var out AccountLimits
	if err := c.get(ctx, "/user/limits", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetAllowedIPs calls GET /ddos/getAllowedIps.
func (c *Client) GetAllowedIPs(ctx context.Context) ([]string, error) {
	var out AuthorizedIPs
	if err := c.get(ctx, "/ddos/getAllowedIps", &out); err != nil {
		return nil, err
	}
	return out.AuthorizedIPs, nil
}

// GetConfig calls GET /ddos/config/{IP}.
func (c *Client) GetConfig(ctx context.Context, ip string) (*Config, error) {
	var out Config
	if err := c.get(ctx, "/ddos/config/"+esc(ip), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetMetricsRaw calls GET /ddos/metrics/{IP}. The response shape
// (IPMetrics) is not defined in the upstream spec, so it's returned as raw
// decoded JSON for the caller to flatten defensively.
func (c *Client) GetMetricsRaw(ctx context.Context, ip string) (interface{}, error) {
	var out interface{}
	if err := c.get(ctx, "/ddos/metrics/"+esc(ip), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetAttacksRaw calls GET /ddos/attacks/{IP}. The response shape
// (AttacksForIP) is not defined in the upstream spec; returned as raw
// decoded JSON.
func (c *Client) GetAttacksRaw(ctx context.Context, ip string) (interface{}, error) {
	var out interface{}
	if err := c.get(ctx, "/ddos/attacks/"+esc(ip), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetFirewallRaw calls GET /ddos/firewall/{IP}. The response shape
// (FWForIP) is not defined in the upstream spec; returned as raw decoded
// JSON.
func (c *Client) GetFirewallRaw(ctx context.Context, ip string) (interface{}, error) {
	var out interface{}
	if err := c.get(ctx, "/ddos/firewall/"+esc(ip), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetTunnels calls GET /tunnel.
func (c *Client) GetTunnels(ctx context.Context) ([]TunnelConf, error) {
	var out GetTunnelsReply
	if err := c.get(ctx, "/tunnel", &out); err != nil {
		return nil, err
	}
	return out.AccountTunnels, nil
}

// GetAllowedProxies calls GET /minecraft/getAllowedProxies.
func (c *Client) GetAllowedProxies(ctx context.Context) ([]string, error) {
	var out AllowedProxiesList
	if err := c.get(ctx, "/minecraft/getAllowedProxies", &out); err != nil {
		return nil, err
	}
	return out.AllowedProxies, nil
}

// GetProxy calls GET /minecraft/proxy/{uuid}.
func (c *Client) GetProxy(ctx context.Context, id string) (*ProxyConf, error) {
	var out ProxyConf
	if err := c.get(ctx, "/minecraft/proxy/"+esc(id), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetProxyPorts calls GET /minecraft/proxy/{proxyID}/port.
func (c *Client) GetProxyPorts(ctx context.Context, id string) (*ProxyPortConf, error) {
	var out ProxyPortConf
	if err := c.get(ctx, "/minecraft/proxy/"+esc(id)+"/port", &out); err != nil {
		return nil, err
	}
	return &out, nil
}
