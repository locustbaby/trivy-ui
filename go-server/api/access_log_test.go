package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"trivy-ui/utils"
)

// captureStdout redirects os.Stdout and os.Stderr while fn runs and returns
// what was written (warnings/errors are logged to stderr).
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	originalOut, originalErr := os.Stdout, os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout, os.Stderr = writer, writer
	defer func() { os.Stdout, os.Stderr = originalOut, originalErr }()

	fn()

	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read captured output: %v", err)
	}
	return string(data)
}

func TestAccessLogHandler_LogsUserIPAndUserAgent(t *testing.T) {
	utils.SetLogLevel(utils.LevelDebug)
	defer utils.SetLogLevel(utils.LevelInfo)

	handler := AccessLogHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	output := captureStdout(t, func() {
		// Trust the httptest peer address so X-Forwarded-For is honored.
		t.Setenv("TRUSTED_PROXY_CIDRS", "192.0.2.0/24,127.0.0.0/8")
		req := httptest.NewRequest(http.MethodGet, "/api/v1/reports?type=vulns&page=2", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
		req.Header.Set("X-Forwarded-For", "203.0.113.7")
		handler.ServeHTTP(httptest.NewRecorder(), req)
	})

	lines := strings.Split(strings.TrimSpace(output), "\n")
	var entry map[string]interface{}
	for _, line := range lines {
		var candidate map[string]interface{}
		if err := json.Unmarshal([]byte(line), &candidate); err == nil && candidate["message"] == "request" {
			entry = candidate
		}
	}
	if entry == nil {
		t.Fatalf("no access log entry found in output:\n%s", output)
	}
	fields := entry["fields"].(map[string]interface{})
	if fields["user_agent"] != "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" {
		t.Errorf("user_agent = %v", fields["user_agent"])
	}
	if fields["src_ip"] != "203.0.113.7" {
		t.Errorf("src_ip (trusted proxy) = %v", fields["src_ip"])
	}
	// The duplicated "ip" field was removed; only src_ip remains.
	if _, dup := fields["ip"]; dup {
		t.Errorf("legacy duplicate field \"ip\" should not be logged anymore")
	}
	if fields["user"] != "anonymous" {
		t.Errorf("user without auth should be anonymous, got %v", fields["user"])
	}
	if entry["level"] != string(utils.LevelInfo) {
		t.Errorf("2xx access entry level = %v, want info", entry["level"])
	}
}

func TestAccessLogHandler_SkipsNoisyPathsAtInfoLevel(t *testing.T) {
	utils.SetLogLevel(utils.LevelInfo)
	defer utils.SetLogLevel(utils.LevelDebug)

	handler := AccessLogHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, path := range []string{"/healthz", "/readyz", "/favicon.ico", "/assets/index-abc123.js"} {
		output := captureStdout(t, func() {
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
		})
		if strings.Contains(output, `"message":"request"`) {
			t.Errorf("%s should not be logged at info level, got %s", path, output)
		}
	}
}

func TestAccessLogHandler_DebugLevelStillLogsNoisyPaths(t *testing.T) {
	utils.SetLogLevel(utils.LevelDebug)
	defer utils.SetLogLevel(utils.LevelInfo)

	handler := AccessLogHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	output := captureStdout(t, func() {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	})
	if !strings.Contains(output, `"path":"/healthz"`) {
		t.Errorf("debug level should still log health probes, got %s", output)
	}
}

func TestAccessLogHandler_LevelByStatus(t *testing.T) {
	utils.SetLogLevel(utils.LevelError)
	defer utils.SetLogLevel(utils.LevelInfo)

	handler := AccessLogHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/client-error":
			w.WriteHeader(http.StatusNotFound)
		case "/api/v1/server-error":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))

	// At error level, only the 5xx request produces output.
	output := captureStdout(t, func() {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/client-error", nil))
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/server-error", nil))
	})

	if !strings.Contains(output, `"level":"error"`) {
		t.Errorf("5xx should be logged at error level, got %s", output)
	}
	if strings.Contains(output, `"level":"warning"`) || strings.Contains(output, `"status":404`) {
		t.Errorf("4xx should be filtered out at error level, got %s", output)
	}
}
