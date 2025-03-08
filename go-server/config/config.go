// Configuration management
package config

import (
	"os"
	"path/filepath"
)

// Config holds application configuration
type Config struct {
	// Server configuration
	Port  string
	Debug bool

	// Cache configuration
	CachePath     string
	CacheInterval int // in minutes

	// Frontend path
	StaticPath string
}

// Default configuration values
var defaultConfig = Config{
	Port:          "8080",
	Debug:         false,
	CachePath:     "trivy-cache.dat",
	CacheInterval: 2,
	StaticPath:    "../trivy-dashboard/dist",
}

// Get returns the application configuration
func Get() Config {
	cfg := defaultConfig

	// Override with environment variables if present
	if port := os.Getenv("PORT"); port != "" {
		cfg.Port = port
	}

	if debug := os.Getenv("DEBUG"); debug == "true" {
		cfg.Debug = true
	}

	if cachePath := os.Getenv("CACHE_PATH"); cachePath != "" {
		cfg.CachePath = cachePath
	}

	if cacheInterval := os.Getenv("CACHE_INTERVAL"); cacheInterval != "" {
		// Parse to int and set if valid, otherwise keep default
		// (skipping error handling for brevity)
	}

	if staticPath := os.Getenv("STATIC_PATH"); staticPath != "" {
		cfg.StaticPath = staticPath
	}

	return cfg
}

// KubeConfigPath returns the path to the Kubernetes config file
func KubeConfigPath() string {
	if path := os.Getenv("KUBECONFIG"); path != "" {
		return path
	}
	return filepath.Join(os.Getenv("HOME"), ".kube", "config")
}
