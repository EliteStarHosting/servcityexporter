// Package config loads exporter settings from environment variables.
package config

import (
	"fmt"
	"os"
	"time"
)

// Config holds every tunable of the exporter.
type Config struct {
	// APIBaseURL is the ServCity API root, no trailing slash.
	APIBaseURL string
	// APIKeyID and APIKeySecret together authenticate every request (Basic
	// auth: id as username, secret as password) - both come from the
	// {"id": ..., "secret": ...} response of POST /user/loginapikey.
	// Neither is ever logged.
	APIKeyID     string
	APIKeySecret string
	// ListenAddr is the address the /metrics HTTP server binds to.
	ListenAddr string
	// RequestTimeout bounds a single HTTP call to the ServCity API.
	RequestTimeout time.Duration
	// FastInterval is how often per-IP DDoS data and tunnel counters are
	// refreshed.
	FastInterval time.Duration
	// SlowInterval is how often account limits, the authorized-IP list,
	// and the Minecraft proxy list/config are refreshed.
	SlowInterval time.Duration
}

// Load reads configuration from the environment, applying defaults, and
// validates required fields.
func Load() (Config, error) {
	cfg := Config{
		APIBaseURL:   getEnv("SERVCITY_API_BASE_URL", "https://servcity.org/uapi"),
		APIKeyID:     os.Getenv("SERVCITY_API_KEY_ID"),
		APIKeySecret: os.Getenv("SERVCITY_API_KEY_SECRET"),
		ListenAddr:   getEnv("SERVCITY_LISTEN_ADDR", ":9420"),
	}

	if cfg.APIKeyID == "" {
		return Config{}, fmt.Errorf("SERVCITY_API_KEY_ID is required")
	}
	if cfg.APIKeySecret == "" {
		return Config{}, fmt.Errorf("SERVCITY_API_KEY_SECRET is required")
	}

	var err error
	if cfg.RequestTimeout, err = getDuration("SERVCITY_REQUEST_TIMEOUT", 10*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.FastInterval, err = getDuration("SERVCITY_POLL_INTERVAL", 30*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.SlowInterval, err = getDuration("SERVCITY_DISCOVERY_INTERVAL", 5*time.Minute); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getDuration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", key, v, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("invalid %s %q: must be positive", key, v)
	}
	return d, nil
}
