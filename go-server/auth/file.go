package auth

import (
	"context"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type FileConfig struct {
	Version string               `yaml:"version"`
	Users   map[string]FileUser  `yaml:"users"`
	Groups  map[string]FileGroup `yaml:"groups"`
}

type FileUser struct {
	PasswordHash string      `yaml:"passwordHash"`
	Groups       []string    `yaml:"groups"`
	Scopes       []ScopeRule `yaml:"scopes"`
}

type FileGroup struct {
	Scopes []ScopeRule `yaml:"scopes"`
}

type FileStore struct {
	users     map[string]FileUser
	groups    map[string]FileGroup
	bcryptSem chan struct{}
}

const dummyPasswordHash = "$2b$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

func LoadFileStore(path string) (*FileStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read auth config %q: %w", path, err)
	}
	var config FileConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse auth config %q: %w", path, err)
	}
	if config.Version != "" && config.Version != "v1" {
		return nil, fmt.Errorf("unsupported auth config version %q", config.Version)
	}
	if len(config.Users) == 0 {
		return nil, fmt.Errorf("auth config must define at least one user")
	}
	if config.Groups == nil {
		config.Groups = map[string]FileGroup{}
	}
	store := &FileStore{users: make(map[string]FileUser), groups: config.Groups, bcryptSem: make(chan struct{}, 4)}
	for username, user := range config.Users {
		normalized := strings.ToLower(strings.TrimSpace(username))
		if normalized == "" || normalized != username {
			return nil, fmt.Errorf("user name %q must be normalized lowercase without surrounding spaces", username)
		}
		if user.PasswordHash == "" {
			return nil, fmt.Errorf("user %q has an empty passwordHash", username)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte("config-validation-placeholder")); err == nil || err == bcrypt.ErrMismatchedHashAndPassword {
			// A valid bcrypt hash returns a mismatch for the placeholder password.
		} else {
			return nil, fmt.Errorf("user %q has an invalid bcrypt passwordHash: %w", username, err)
		}
		if err := ValidateScopeRules(user.Scopes); err != nil {
			return nil, fmt.Errorf("user %q: %w", username, err)
		}
		for _, group := range user.Groups {
			if _, ok := config.Groups[group]; !ok {
				return nil, fmt.Errorf("user %q references unknown group %q", username, group)
			}
		}
		for groupName, group := range config.Groups {
			if strings.TrimSpace(groupName) == "" {
				return nil, fmt.Errorf("group name cannot be empty")
			}
			if err := ValidateScopeRules(group.Scopes); err != nil {
				return nil, fmt.Errorf("group %q: %w", groupName, err)
			}
		}
		store.users[username] = user
	}
	return store, nil
}

func (s *FileStore) Authenticate(_ context.Context, username, password string) (Principal, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	user, ok := s.users[username]
	hash := dummyPasswordHash
	if ok {
		hash = user.PasswordHash
	}
	if s.bcryptSem != nil {
		s.bcryptSem <- struct{}{}
		defer func() { <-s.bcryptSem }()
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil || !ok {
		return Principal{}, fmt.Errorf("invalid credentials")
	}
	return Principal{Subject: username, Username: username, Groups: append([]string(nil), user.Groups...)}, nil
}

func (s *FileStore) Resolve(_ context.Context, subject string) (Principal, error) {
	username := strings.ToLower(strings.TrimSpace(subject))
	user, ok := s.users[username]
	if !ok {
		return Principal{}, fmt.Errorf("unknown subject")
	}
	return Principal{Subject: username, Username: username, Groups: append([]string(nil), user.Groups...)}, nil
}

func (s *FileStore) ScopesFor(_ context.Context, principal Principal) (ScopeSnapshot, error) {
	user, ok := s.users[principal.Username]
	if !ok {
		return ScopeSnapshot{}, fmt.Errorf("unknown principal")
	}
	rules := append([]ScopeRule(nil), user.Scopes...)
	for _, groupName := range user.Groups {
		group, ok := s.groups[groupName]
		if !ok {
			return ScopeSnapshot{}, fmt.Errorf("unknown group %q", groupName)
		}
		rules = append(rules, group.Scopes...)
	}
	return NewScopeSnapshot(rules), nil
}

func HashPassword(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
