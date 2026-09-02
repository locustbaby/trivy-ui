package auth

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Service struct {
	mode     string
	identity IdentityProvider
	policy   PolicyProvider
	session  SessionManager
}

type Config struct {
	Mode            string
	Backend         string
	FilePath        string
	SessionSecret   string
	SessionDuration time.Duration
	CookieSecure    bool
}

func ConfigFromEnv() (Config, error) {
	duration, err := ParseDuration(os.Getenv("AUTH_SESSION_DURATION"), 12*time.Hour)
	if err != nil {
		return Config{}, fmt.Errorf("parse AUTH_SESSION_DURATION: %w", err)
	}
	secure, err := strconv.ParseBool(getEnv("AUTH_COOKIE_SECURE", "true"))
	if err != nil {
		return Config{}, fmt.Errorf("parse AUTH_COOKIE_SECURE: %w", err)
	}
	return Config{
		Mode:            getEnv("AUTH_MODE", "none"),
		Backend:         getEnv("AUTH_LOCAL_BACKEND", "file"),
		FilePath:        getEnv("AUTH_FILE_PATH", "/etc/trivy-ui/auth/auth.yaml"),
		SessionSecret:   os.Getenv("AUTH_SESSION_SECRET"),
		SessionDuration: duration,
		CookieSecure:    secure,
	}, nil
}

func NewService(cfg Config) (*Service, error) {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "none" {
		return &Service{mode: "none"}, nil
	}
	if mode != "local" {
		return nil, fmt.Errorf("unsupported auth mode %q", cfg.Mode)
	}
	if cfg.Backend != "file" {
		return nil, fmt.Errorf("unsupported local auth backend %q", cfg.Backend)
	}
	store, err := LoadFileStore(cfg.FilePath)
	if err != nil {
		return nil, err
	}
	manager, err := NewCookieSessionManager([]byte(cfg.SessionSecret), cfg.SessionDuration, cfg.CookieSecure)
	if err != nil {
		return nil, err
	}
	return &Service{mode: "local", identity: store, policy: store, session: manager}, nil
}

func (s *Service) Mode() string { return s.mode }

func (s *Service) IsEnabled() bool { return s.mode != "none" }

func (s *Service) Authenticate(ctx context.Context, username, password string) (Principal, error) {
	if !s.IsEnabled() {
		return Principal{Subject: "anonymous", Username: "anonymous"}, nil
	}
	return s.identity.Authenticate(ctx, username, password)
}

func (s *Service) Resolve(ctx context.Context, subject string) (Principal, ScopeSnapshot, error) {
	if !s.IsEnabled() {
		return Principal{Subject: "anonymous", Username: "anonymous"}, UnrestrictedScope(), nil
	}
	principal, err := s.identity.Resolve(ctx, subject)
	if err != nil {
		return Principal{}, ScopeSnapshot{}, err
	}
	scope, err := s.policy.ScopesFor(ctx, principal)
	if err != nil {
		return Principal{}, ScopeSnapshot{}, err
	}
	return principal, scope, nil
}

func (s *Service) Session() SessionManager { return s.session }

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
