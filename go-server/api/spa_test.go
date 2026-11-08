package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSpaHandlerCachingAndStaleAssets(t *testing.T) {
	static := t.TempDir()
	if err := os.MkdirAll(filepath.Join(static, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(static, "index.html"), []byte("<html>app</html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(static, "assets", "index-abc123.js"), []byte("console.log(1)"), 0o600); err != nil {
		t.Fatal(err)
	}
	handler := SpaHandler(static)
	get := func(path string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		handler(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		return recorder
	}

	for _, path := range []string{"/", "/?cluster=a", "/some/route"} {
		recorder := get(path)
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "app") || recorder.Header().Get("Cache-Control") != "no-cache" {
			t.Fatalf("%s: %d %q cache=%q", path, recorder.Code, recorder.Body.String(), recorder.Header().Get("Cache-Control"))
		}
	}

	recorder := get("/assets/index-abc123.js")
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("hashed asset: %d cache=%q", recorder.Code, recorder.Header().Get("Cache-Control"))
	}

	recorder = get("/assets/ReportDetails-old.js")
	if recorder.Code != http.StatusNotFound || strings.Contains(recorder.Body.String(), "<html>") {
		t.Fatalf("a missing asset must be 404, not the app page: %d %q", recorder.Code, recorder.Body.String())
	}

	if recorder := get("/api/v1/unknown"); recorder.Code != http.StatusNotFound {
		t.Fatalf("unknown API path: %d", recorder.Code)
	}
}
