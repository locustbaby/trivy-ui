// Router configuration
package api

import (
	"net/http"
	"strings"

	"trivy-ui/config"
)

// SetupRouter configures all the API routes
func SetupRouter() *http.ServeMux {
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/namespaces", FetchNamespaces)
	mux.HandleFunc("/vulnerability-reports", FetchVulnerabilityReports)
	mux.HandleFunc("/report-details", FetchReportDetails)
	mux.HandleFunc("/report-history", FetchReportHistory)

	// Cluster management endpoints
	mux.HandleFunc("/clusters", ClustersHandler)
	mux.HandleFunc("/clusters/", ClusterHandler)

	// SPA handler for frontend
	cfg := config.Get()
	mux.HandleFunc("/", SpaHandler(cfg.StaticPath))

	return mux
}

// ClustersHandler handles the /clusters endpoint with both GET and POST methods
func ClustersHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		FetchClusters(w, r)
	case http.MethodPost:
		AddCluster(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ClusterHandler handles the /clusters/{name} endpoint with DELETE and PUT methods
func ClusterHandler(w http.ResponseWriter, r *http.Request) {
	// Get cluster name from URL path
	clusterName := strings.TrimPrefix(r.URL.Path, "/clusters/")
	if clusterName == "" {
		http.Error(w, "Cluster name is required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		DeleteCluster(w, r)
	case http.MethodPut:
		UpdateCluster(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
