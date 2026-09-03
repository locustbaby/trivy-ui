package utils

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnsureDirectoryExists(t *testing.T) {
	tempDir := t.TempDir()
	targetFile := filepath.Join(tempDir, "sub1", "sub2", "file.txt")

	if err := EnsureDirectoryExists(targetFile); err != nil {
		t.Fatalf("EnsureDirectoryExists failed: %v", err)
	}

	dir := filepath.Dir(targetFile)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("expected directory %q to exist as a dir", dir)
	}

	// Calling again on existing directory should succeed without error
	if err := EnsureDirectoryExists(targetFile); err != nil {
		t.Fatalf("EnsureDirectoryExists on existing dir failed: %v", err)
	}
}

func TestPrettyPrint(t *testing.T) {
	data := map[string]interface{}{
		"name": "trivy-ui",
		"port": 8080,
	}
	out := PrettyPrint(data)
	if !strings.Contains(out, "\"name\": \"trivy-ui\"") || !strings.Contains(out, "\"port\": 8080") {
		t.Fatalf("unexpected PrettyPrint output: %s", out)
	}

	// Unmarshallable value
	bad := map[string]interface{}{
		"fn": func() {},
	}
	badOut := PrettyPrint(bad)
	if !strings.HasPrefix(badOut, "Error:") {
		t.Fatalf("expected error string for unmarshallable value, got: %s", badOut)
	}
}

func captureOutput(f func()) string {
	oldOut := os.Stdout
	oldErr := os.Stderr

	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()

	os.Stdout = wOut
	os.Stderr = wErr

	f()

	wOut.Close()
	wErr.Close()
	os.Stdout = oldOut
	os.Stderr = oldErr

	var buf bytes.Buffer
	io.Copy(&buf, rOut)
	io.Copy(&buf, rErr)
	return buf.String()
}

func TestLoggerLevelsAndFormat(t *testing.T) {
	SetLogLevel(LevelDebug)
	if !IsDebugLevel() {
		t.Fatalf("expected debug level to be true")
	}

	out := captureOutput(func() {
		LogDebug("debug msg", map[string]interface{}{"foo": "bar"})
		LogInfo("info msg", nil)
		LogWarning("warning msg", nil)
		LogError("error msg", nil)
		LogAccess("req-123", "127.0.0.1", "admin", "Go-http-client", "GET", "/api/v1/reports", "prod", 200, 1024, 15*time.Millisecond)
	})

	if !strings.Contains(out, "debug msg") || !strings.Contains(out, "info msg") ||
		!strings.Contains(out, "warning msg") || !strings.Contains(out, "error msg") ||
		!strings.Contains(out, "req-123") {
		t.Fatalf("expected all log messages in output, got: %s", out)
	}

	// Set level to Error: Debug/Info/Warning must not be logged
	SetLogLevel(LevelError)
	if IsDebugLevel() {
		t.Fatalf("expected debug level to be false when set to error")
	}

	out = captureOutput(func() {
		LogDebug("should not appear", nil)
		LogInfo("should not appear", nil)
		LogWarning("should not appear", nil)
		LogError("critical error", map[string]interface{}{"code": 500})
	})

	if strings.Contains(out, "should not appear") {
		t.Fatalf("filtered messages appeared in output: %s", out)
	}
	if !strings.Contains(out, "critical error") {
		t.Fatalf("error message missing from output: %s", out)
	}

	// Parse from env fallback
	os.Setenv("LOG_LEVEL", "warn")
	SetLogLevel("unknown-level")
	if IsDebugLevel() {
		t.Fatalf("expected debug to be false after env warn")
	}
	os.Unsetenv("LOG_LEVEL")
}
