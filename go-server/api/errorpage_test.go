package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCustomErrorPageDisabled(t *testing.T) {
	page := newCustomErrorPage("")
	if page != nil {
		t.Fatal("expected nil page when no path configured")
	}
}

func TestCustomErrorPageServesAndHotReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "error.html")
	if err := os.WriteFile(path, []byte("<h1>v1</h1>"), 0600); err != nil {
		t.Fatal(err)
	}
	page := newCustomErrorPage(path)

	rec := httptest.NewRecorder()
	page.handler(rec, httptest.NewRequest(http.MethodGet, "/error-page.html", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("content-type = %q", got)
	}
	if rec.Body.String() != "<h1>v1</h1>" {
		t.Fatalf("body = %q", rec.Body.String())
	}

	// Hot reload on mtime change.
	if err := os.WriteFile(path, []byte("<h1>v2 contact ops</h1>"), 0600); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(path, time.Now().Add(time.Second), time.Now().Add(time.Second))
	rec = httptest.NewRecorder()
	page.handler(rec, httptest.NewRequest(http.MethodGet, "/error-page.html", nil))
	if rec.Body.String() != "<h1>v2 contact ops</h1>" {
		t.Fatalf("hot reload failed, body = %q", rec.Body.String())
	}
}

func TestCustomErrorPageMissingFileIs404(t *testing.T) {
	page := newCustomErrorPage(filepath.Join(t.TempDir(), "absent.html"))
	rec := httptest.NewRecorder()
	page.handler(rec, httptest.NewRequest(http.MethodGet, "/error-page.html", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestCustomErrorPageRejectsPost(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "error.html")
	if err := os.WriteFile(path, []byte("<h1>x</h1>"), 0600); err != nil {
		t.Fatal(err)
	}
	page := newCustomErrorPage(path)
	rec := httptest.NewRecorder()
	page.handler(rec, httptest.NewRequest(http.MethodPost, "/error-page.html", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestWriteErrorEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "req-123")
	writeError(rec, httptest.NewRequest(http.MethodGet, "/api/v1/reports?type=x", nil),
		http.StatusForbidden, ErrAccessDenied, "report access denied")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	var body Response
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error == nil || body.Error.Type != string(ErrAccessDenied) {
		t.Fatalf("error type = %+v, want %s", body.Error, ErrAccessDenied)
	}
	if body.Error.RequestID != "req-123" {
		t.Fatalf("request id = %q", body.Error.RequestID)
	}
}

func TestCustomErrorPageDeletedFileStopsServing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "error.html")
	if err := os.WriteFile(path, []byte("<h1>v1</h1>"), 0600); err != nil {
		t.Fatal(err)
	}
	page := newCustomErrorPage(path)
	rec := httptest.NewRecorder()
	page.handler(rec, httptest.NewRequest(http.MethodGet, "/error-page.html", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(filepath.Dir(path), time.Now().Add(time.Second), time.Now().Add(time.Second))
	rec = httptest.NewRecorder()
	page.handler(rec, httptest.NewRequest(http.MethodGet, "/error-page.html", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 after deletion", rec.Code)
	}
}

func TestLoadErrorPageConfigFromEnv(t *testing.T) {
	t.Setenv("ERROR_PAGE_CONFIG", "")
	if err := LoadErrorPageConfigFromEnv(); err != nil {
		t.Fatalf("empty config should load fine: %v", err)
	}
	if GetErrorPageConfig() != nil {
		t.Fatal("expected nil config when env unset")
	}

	valid := `{"title":"Down","message":"Call ops","items":[{"type":"email","label":"Email","value":"ops@example.com"},{"type":"link","label":"Runbook","value":"https://wiki.example.com/rb"}]}`
	t.Setenv("ERROR_PAGE_CONFIG", valid)
	if err := LoadErrorPageConfigFromEnv(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cfg := GetErrorPageConfig()
	if cfg == nil || cfg.Title != "Down" || len(cfg.Items) != 2 {
		t.Fatalf("config = %+v", cfg)
	}

	cases := []string{
		`{"title":""}`,
		`{"title":"x","items":[{"type":"sms","label":"x","value":"y"}]}`,
		`{"title":"x","items":[{"type":"link","label":"x","value":"javascript:alert(1)"}]}`,
		`{"title":"x","items":[{"type":"email","label":"x","value":"not-an-email"}]}`,
		`{invalid json}`,
	}
	for _, raw := range cases {
		t.Setenv("ERROR_PAGE_CONFIG", raw)
		if err := LoadErrorPageConfigFromEnv(); err == nil {
			t.Errorf("expected error for %s", raw)
		}
	}
}
