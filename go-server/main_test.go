package main

import (
	"os"
	"path/filepath"
	"testing"

	"trivy-ui/auth"
)

func TestMountedKubeconfigPathConfinesSecretFiles(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "..data")
	if err := os.Mkdir(data, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "cluster.yaml"), []byte("apiVersion: v1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..data", "cluster.yaml"), filepath.Join(dir, "cluster.yaml")); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.yaml")
	if err := os.WriteFile(outside, []byte("apiVersion: v1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "outside.yaml")); err != nil {
		t.Fatal(err)
	}
	if got, err := mountedKubeconfigPath(dir, "cluster.yaml"); err != nil || got != filepath.Join(dir, "cluster.yaml") {
		t.Fatalf("projected Secret file = %q, %v", got, err)
	}
	for _, key := range []string{".", "..", "outside.yaml", "..data"} {
		if _, err := mountedKubeconfigPath(dir, key); err == nil {
			t.Errorf("accepted invalid kubeconfig key %q", key)
		}
	}
}

func TestCORSSettingsFromEnv(t *testing.T) {
	t.Setenv("CORS_ALLOWED_ORIGINS", " https://dashboard.example.com, https://admin.example.com ")
	settings := corsSettingsFromEnv()
	if !settings.allowCredentials {
		t.Fatal("explicit origins must enable credentialed requests")
	}
	if len(settings.allowedOrigins) != 2 || settings.allowedOrigins[0] != "https://dashboard.example.com" || settings.allowedOrigins[1] != "https://admin.example.com" {
		t.Fatalf("allowed origins = %v", settings.allowedOrigins)
	}

	t.Setenv("CORS_ALLOWED_ORIGINS", "*")
	settings = corsSettingsFromEnv()
	if settings.allowCredentials {
		t.Fatal("wildcard origin must not enable credentials")
	}
}

func TestApplyCORSCookiePolicy(t *testing.T) {
	credentials := corsSettings{allowCredentials: true}
	cfg := auth.Config{CookieSameSite: "lax"}
	applyCORSCookiePolicy(&cfg, credentials, false)
	if cfg.CookieSameSite != "none" {
		t.Fatalf("derived SameSite policy = %q, want none", cfg.CookieSameSite)
	}

	cfg.CookieSameSite = "strict"
	applyCORSCookiePolicy(&cfg, credentials, true)
	if cfg.CookieSameSite != "strict" {
		t.Fatalf("explicit SameSite policy = %q, want strict", cfg.CookieSameSite)
	}
}
