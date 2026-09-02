package main

import (
	"testing"

	"trivy-ui/auth"
)

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
