// Router configuration
package api

import (
	"net/http"

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

	// SPA handler for frontend
	cfg := config.Get()
	mux.HandleFunc("/", SpaHandler(cfg.StaticPath))

	return mux
}
