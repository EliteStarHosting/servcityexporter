package servcity

import "fmt"

// AuthError indicates the API rejected the configured credentials (HTTP
// 401). Callers should treat this as a configuration problem, not a
// transient failure: retrying immediately won't help, so pollers surface
// it distinctly instead of spinning on it.
type AuthError struct {
	Path       string
	StatusCode int
	Body       string
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("servcity: authentication failed for %s (HTTP %d): %s", e.Path, e.StatusCode, truncate(e.Body, 300))
}

// APIError is any other non-2xx response from the API.
type APIError struct {
	Path       string
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("servcity: request to %s failed (HTTP %d): %s", e.Path, e.StatusCode, truncate(e.Body, 300))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
