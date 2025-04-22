// Main application entry point - Trivy UI server bootstraps components and starts HTTP server
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/rs/cors"

	"trivy-ui/api"
	"trivy-ui/config"
	"trivy-ui/data"
)

func main() {
	// Display version information
	fmt.Printf("Trivy UI Server v%s\n", GetVersion())

	// Load configuration
	fmt.Println("Configuration loaded")
	cfg := config.Get()

	// Create data directory
	dataDir := filepath.Join(os.TempDir(), "trivy-ui", "data")
	fmt.Printf("Creating data directory at %s\n", dataDir)
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	// Initialize database
	dbPath := filepath.Join(dataDir, "trivy.db")
	fmt.Printf("Initializing database at %s\n", dbPath)
	db, err := data.NewDB(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()
	fmt.Println("Database initialized successfully")

	// Initialize repositories
	repo := data.NewRepository(db)
	clusterRepo := data.NewClusterRepository(db)
	fmt.Println("Repositories initialized")

	// Create router using the API package
	fmt.Println("Creating router")

	// Check for static files in different locations
	staticPath := os.Getenv("STATIC_PATH")
	if staticPath == "" {
		// Try common locations for static files
		possiblePaths := []string{
			"trivy-dashboard/dist",      // Local development path
			"../trivy-dashboard/dist",   // Running from go-server directory
			"/app/trivy-dashboard/dist", // Docker container path
			"web/dist",                  // Original path
		}

		for _, path := range possiblePaths {
			if _, err := os.Stat(path); err == nil {
				staticPath = path
				break
			}
		}

		// If no path found, use the default
		if staticPath == "" {
			staticPath = "trivy-dashboard/dist"
			fmt.Printf("Warning: Static files not found, using default path: %s\n", staticPath)
		}
	}

	// Verify that index.html exists in the static path
	indexPath := filepath.Join(staticPath, "index.html")
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		fmt.Printf("Warning: index.html not found at %s\n", indexPath)
	} else {
		fmt.Printf("Found index.html at %s\n", indexPath)
	}

	fmt.Printf("Using static files from: %s\n", staticPath)
	router := api.NewRouter(repo, clusterRepo, staticPath)
	fmt.Println("Router created")

	// Setup CORS
	corsHandler := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodDelete,
			http.MethodOptions,
		},
		AllowedHeaders: []string{
			"Accept",
			"Authorization",
			"Content-Type",
			"X-CSRF-Token",
		},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	})
	fmt.Println("CORS handler created")

	// Start server
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	fmt.Printf("Server starting on %s\n", addr)
	if err := http.ListenAndServe(addr, corsHandler.Handler(router)); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
