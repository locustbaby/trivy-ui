// Main application entry point - Trivy UI server bootstraps components and starts HTTP server
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/rs/cors"

	"trivy-ui/api"
	"trivy-ui/cache"
	"trivy-ui/kubernetes"
)

func main() {
	// Initialize components
	// Load cache from disk and set up periodic persistence
	cache.Init()
	// Set up Kubernetes API client connections
	kubernetes.InitClient()

	// Setup HTTP router with API endpoints and SPA handler
	router := api.SetupRouter()

	// Add middleware layers (CORS, compression)
	handler := addMiddleware(router)

	// Start HTTP server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Default port if not specified in environment
	}

	fmt.Printf("Server running at http://localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

// addMiddleware adds CORS and compression middleware to the HTTP request pipeline
//
// Parameters:
//   - handler: the inner HTTP handler to wrap with middleware
//
// Returns:
//   - http.Handler: handler wrapped with middleware layers
func addMiddleware(handler http.Handler) http.Handler {
	// Add CORS support for browser security
	corsOptions := cors.Options{
		AllowedOrigins:   []string{"*"},                                                         // Allow all origins
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},                   // Supported HTTP methods
		AllowedHeaders:   []string{"Accept", "Content-Type", "Content-Length", "Authorization"}, // Allowed headers
		AllowCredentials: true,                                                                  // Support credentials
	}
	handler = cors.New(corsOptions).Handler(handler)

	// Add compression to reduce response size
	handler = api.CompressHandler(handler)

	return handler
}
