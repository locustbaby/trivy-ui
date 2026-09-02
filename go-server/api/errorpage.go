package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"trivy-ui/utils"
)

// ErrorPageConfig is the structured variant of the custom error page:
// operators provide plain fields (title, message, contact/link items) via
// the ERROR_PAGE_CONFIG env var and the frontend renders them with its own
// components — no HTML authoring or injection surface involved.
//
// It takes precedence in spirit over nothing: ERROR_PAGE_CONFIG and
// ERROR_PAGE_FILE are independent channels; the UI prefers the structured
// config and falls back to the raw HTML file, then to its built-in screen.
type ErrorPageConfig struct {
	Title   string          `json:"title"`
	Message string          `json:"message"`
	Items   []ErrorPageItem `json:"items,omitempty"`
}

// ErrorPageItem describes one contact/entry on the error page.
// Type must be "email" (Value is an email address, rendered as mailto:) or
// "link" (Value is an absolute http(s) URL).
type ErrorPageItem struct {
	Type  string `json:"type"`
	Label string `json:"label"`
	Value string `json:"value"`
}

var (
	errorPageConfigMu sync.RWMutex
	errorPageConfig   *ErrorPageConfig
)

const (
	errorPageMaxTitleLen   = 200
	errorPageMaxMessageLen = 1000
	errorPageMaxLabelLen   = 100
	errorPageMaxValueLen   = 500
	errorPageMaxItems      = 10
)

// LoadErrorPageConfigFromEnv parses and validates ERROR_PAGE_CONFIG. An empty
// value disables the feature. Invalid configuration returns an error so the
// process can fail fast at startup instead of serving a broken page.
func LoadErrorPageConfigFromEnv() error {
	raw := strings.TrimSpace(os.Getenv("ERROR_PAGE_CONFIG"))
	errorPageConfigMu.Lock()
	defer errorPageConfigMu.Unlock()
	if raw == "" {
		errorPageConfig = nil
		return nil
	}
	var cfg ErrorPageConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return fmt.Errorf("parse ERROR_PAGE_CONFIG: %w", err)
	}
	if err := validateErrorPageConfig(&cfg); err != nil {
		return err
	}
	errorPageConfig = &cfg
	return nil
}

func validateErrorPageConfig(cfg *ErrorPageConfig) error {
	cfg.Title = strings.TrimSpace(cfg.Title)
	cfg.Message = strings.TrimSpace(cfg.Message)
	if cfg.Title == "" || len(cfg.Title) > errorPageMaxTitleLen {
		return fmt.Errorf("ERROR_PAGE_CONFIG: title must be 1-%d characters", errorPageMaxTitleLen)
	}
	if len(cfg.Message) > errorPageMaxMessageLen {
		return fmt.Errorf("ERROR_PAGE_CONFIG: message must be at most %d characters", errorPageMaxMessageLen)
	}
	if len(cfg.Items) > errorPageMaxItems {
		return fmt.Errorf("ERROR_PAGE_CONFIG: at most %d items are allowed", errorPageMaxItems)
	}
	for i, item := range cfg.Items {
		item.Label = strings.TrimSpace(item.Label)
		item.Value = strings.TrimSpace(item.Value)
		switch item.Type {
		case "email":
			if !strings.Contains(item.Value, "@") || strings.ContainsAny(item.Value, " \t\r\n") {
				return fmt.Errorf("ERROR_PAGE_CONFIG: item %d has invalid email %q", i, item.Value)
			}
		case "link":
			u, err := url.Parse(item.Value)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("ERROR_PAGE_CONFIG: item %d has invalid link %q (absolute http(s) URL required)", i, item.Value)
			}
		default:
			return fmt.Errorf("ERROR_PAGE_CONFIG: item %d has unsupported type %q (want email or link)", i, item.Type)
		}
		if item.Label == "" || len(item.Label) > errorPageMaxLabelLen {
			return fmt.Errorf("ERROR_PAGE_CONFIG: item %d label must be 1-%d characters", i, errorPageMaxLabelLen)
		}
		if len(item.Value) > errorPageMaxValueLen {
			return fmt.Errorf("ERROR_PAGE_CONFIG: item %d value must be at most %d characters", i, errorPageMaxValueLen)
		}
		cfg.Items[i] = item
	}
	return nil
}

// GetErrorPageConfig returns the parsed configuration, or nil when unset.
func GetErrorPageConfig() *ErrorPageConfig {
	errorPageConfigMu.RLock()
	defer errorPageConfigMu.RUnlock()
	return errorPageConfig
}

// customErrorPage serves an operator-provided HTML document at
// /error-page.html. Operators can use it to present contact details,
// runbooks or related documentation on authentication/authorization and
// availability failures; the frontend renders it in place of its default
// error screens whenever it is configured.
//
// Trust model: the file is supplied by whoever deploys the application, so
// it is rendered by the frontend with the same trust level as the app
// bundle itself. Never point ERROR_PAGE_FILE at user-writable storage.
//
// The file is re-read automatically when its modification time changes, so
// updates take effect without a restart.
type customErrorPage struct {
	mu      sync.RWMutex
	path    string
	content []byte
	modTime time.Time
	size    int64
}

func newCustomErrorPage(path string) *customErrorPage {
	if path == "" {
		return nil
	}
	return &customErrorPage{path: path}
}

// loadLocked re-reads the file if it changed on disk. Returns the current
// content (nil when the file is missing or unreadable — a deleted file stops
// being served rather than pinning a stale copy).
func (c *customErrorPage) current() []byte {
	if c == nil {
		return nil
	}
	info, err := os.Stat(c.path)
	if err != nil {
		if os.IsNotExist(err) {
			c.mu.Lock()
			c.content = nil
			c.modTime = time.Time{}
			c.size = 0
			c.mu.Unlock()
			return nil
		}
		return c.snapshot()
	}
	c.mu.RLock()
	unchanged := !info.ModTime().After(c.modTime) && info.Size() == c.size && c.content != nil
	c.mu.RUnlock()
	if unchanged {
		return c.snapshot()
	}

	data, err := os.ReadFile(c.path)
	if err != nil {
		utils.LogWarning("custom_error_page_load_failed", map[string]interface{}{
			"path":  c.path,
			"error": err.Error(),
		})
		return c.snapshot()
	}
	c.mu.Lock()
	c.content = data
	c.modTime = info.ModTime()
	c.size = info.Size()
	c.mu.Unlock()
	return data
}

func (c *customErrorPage) snapshot() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.content == nil {
		return nil
	}
	return bytes.Clone(c.content)
}

func (c *customErrorPage) handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	content := c.current()
	if len(content) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Hot-reloadable: never let intermediaries or the browser pin a version.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(content)
	}
}
