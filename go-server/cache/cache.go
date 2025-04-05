// Cache implementation provides persistent caching functionality for API responses
package cache

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	gocache "github.com/patrickmn/go-cache"
)

// Store is the global cache instance that holds all cached data
var Store *gocache.Cache

// cachePath defines the file path for cache persistence
var cachePath string = "trivy-cache.dat"

// Config holds application configuration settings
type Config struct {
	// Server configuration
	Port  string // HTTP port to listen on
	Debug bool   // Enable debug logging

	// Cache configuration
	CachePath     string // Path to save cache data
	CacheInterval int    // How often to save cache to disk (in minutes)

	// Frontend path
	StaticPath string // Path to static frontend assets
}

// Default configuration values
var defaultConfig = Config{
	Port:          "8080",
	Debug:         false,
	CachePath:     "trivy-cache.dat",
	CacheInterval: 2,
	StaticPath:    "../trivy-dashboard/dist", // Updated path
}

// Get returns the application configuration
// Merges default values with environment variables when available
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

// Init initializes the cache system
// - Creates the memory cache
// - Loads previous cache data from disk (if available)
// - Sets up periodic cache saves to disk
// - Configures signal handlers for graceful shutdown
func Init() {
	// Create cache with default expiration of 5 minutes and cleanup every 10 minutes
	Store = gocache.New(5*time.Minute, 10*time.Minute)

	// Try to load previous cache from disk
	err := Store.LoadFile(cachePath)
	if err != nil {
		log.Printf("Could not load cache from disk: %v", err)
	} else {
		log.Printf("Cache loaded from disk: %s", cachePath)
	}

	// Set up periodic saving to disk
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			if err := Store.SaveFile(cachePath); err != nil {
				log.Printf("Error saving cache to disk: %v", err)
			} else {
				log.Printf("Cache saved to disk: %s", cachePath)
			}
		}
	}()

	// Handle graceful shutdown to save cache
	setupSignalHandler()
}

// setupSignalHandler configures operating system signal handling
// to ensure the cache is persisted before the application exits
func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Received shutdown signal, saving cache before exit...")
		if err := Store.SaveFile(cachePath); err != nil {
			log.Printf("Error saving cache on shutdown: %v", err)
		} else {
			log.Println("Cache saved successfully")
		}
		os.Exit(0)
	}()
}

// Cache key helper functions
// -------------------------------

// NamespacesKey returns the cache key for storing namespaces
func NamespacesKey(cluster string) string {
	return "namespaces_" + cluster
}

// ReportsKey generates a cache key for vulnerability reports
// Includes all query parameters to ensure unique caching
// Parameters:
//   - namespace: Kubernetes namespace
//   - limit: maximum number of results to return
//   - continueToken: pagination token for subsequent requests
//   - search: search filter text
func ReportsKey(namespace string, limit int64, continueToken, search string) string {
	return fmt.Sprintf("reports_%s_%d_%s_%s", namespace, limit, continueToken, search)
}

// ReportDetailsKey generates a cache key for report details
// Parameters:
//   - namespace: Kubernetes namespace
//   - reportName: name of the vulnerability report
func ReportDetailsKey(namespace, reportName string) string {
	return fmt.Sprintf("report_details_%s_%s", namespace, reportName)
}

// KubeConfigPath returns the path to the Kubernetes config file
// Checks for KUBECONFIG environment variable first, then falls back to default location
func KubeConfigPath() string {
	if path := os.Getenv("KUBECONFIG"); path != "" {
		return path
	}
	return filepath.Join(os.Getenv("HOME"), ".kube", "config")
}
