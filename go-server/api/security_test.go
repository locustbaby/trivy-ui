package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trivy-ui/auth"
	"trivy-ui/config"
)

func securityRouter(t *testing.T) *Router {
	t.Helper()
	static := t.TempDir()
	if err := os.WriteFile(filepath.Join(static, "index.html"), []byte("<html>app</html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	authService, _ := auth.NewService(auth.Config{Mode: "none"})
	cache := &stubCacheService{}
	return NewRouter(nil, static, cache, NewClusterRegistry(cache), config.NewCRDRegistry(), authService, nil)
}

func serve(router *Router, path string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	return recorder
}

func TestSecurityHeadersOnAppAndAPI(t *testing.T) {
	router := securityRouter(t)
	for _, path := range []string{"/", "/healthz"} {
		recorder := serve(router, path)
		if recorder.Header().Get("Content-Security-Policy") != DefaultContentSecurityPolicy {
			t.Fatalf("%s: CSP = %q", path, recorder.Header().Get("Content-Security-Policy"))
		}
		for _, header := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Cross-Origin-Opener-Policy"} {
			if recorder.Header().Get(header) == "" {
				t.Fatalf("%s: missing %s", path, header)
			}
		}
	}
}

func TestContentSecurityPolicyOverride(t *testing.T) {
	t.Setenv("CONTENT_SECURITY_POLICY", "off")
	if recorder := serve(securityRouter(t), "/"); recorder.Header().Get("Content-Security-Policy") != "" {
		t.Fatal("CONTENT_SECURITY_POLICY=off must drop the header")
	}
	t.Setenv("CONTENT_SECURITY_POLICY", "default-src 'self' https://api.example")
	if recorder := serve(securityRouter(t), "/"); recorder.Header().Get("Content-Security-Policy") != "default-src 'self' https://api.example" {
		t.Fatal("a custom policy must be used as given")
	}
}

func TestSwaggerAndCacheStatsOffByDefault(t *testing.T) {
	router := securityRouter(t)
	if body := serve(router, "/swagger/index.html").Body.String(); strings.Contains(strings.ToLower(body), "swagger") {
		t.Fatal("Swagger UI must not be served unless ENABLE_SWAGGER=true")
	}
	if recorder := serve(router, "/api/cache/stats"); recorder.Code != http.StatusNotFound {
		t.Fatalf("cache stats: %d, want 404 unless ENABLE_CACHE_STATS=true", recorder.Code)
	}

	t.Setenv("ENABLE_SWAGGER", "true")
	t.Setenv("ENABLE_CACHE_STATS", "true")
	router = securityRouter(t)
	recorder := serve(router, "/swagger/index.html")
	if !strings.Contains(strings.ToLower(recorder.Body.String()), "swagger") {
		t.Fatalf("ENABLE_SWAGGER=true must serve Swagger UI: %d", recorder.Code)
	}
	if recorder.Header().Get("Content-Security-Policy") != "" {
		t.Fatal("Swagger UI uses inline scripts and must not get the CSP")
	}
	if recorder := serve(router, "/api/cache/stats"); recorder.Code != http.StatusOK {
		t.Fatalf("ENABLE_CACHE_STATS=true: %d", recorder.Code)
	}
}
