// Router configuration
package api

import (
	"net/http"

	"trivy-ui/data"
)

// Router handles HTTP routing
type Router struct {
	mux     *http.ServeMux
	handler *Handler
}

// NewRouter creates a new router
func NewRouter(repo *data.Repository, clusterRepo *data.ClusterRepository, staticPath string) *Router {
	r := &Router{
		mux:     http.NewServeMux(),
		handler: NewHandler(repo, clusterRepo),
	}
	r.Setup(staticPath)
	return r
}

// Setup configures the router
func (r *Router) Setup(staticPath string) {
	// API routes
	// Report types
	r.mux.HandleFunc("/api/report-types", r.handler.GetReportTypes)

	// Reports
	r.mux.HandleFunc("/api/reports", r.handler.GetReports)
	r.mux.HandleFunc("/api/reports/", r.handler.GetReport)

	// Clusters
	r.mux.HandleFunc("/api/clusters", func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodGet:
			r.handler.GetClusters(w, req)
		case http.MethodPost:
			r.handler.SaveCluster(w, req)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	r.mux.HandleFunc("/api/clusters/", func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodDelete:
			r.handler.DeleteCluster(w, req)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Namespaces
	r.mux.HandleFunc("/api/namespaces", r.handler.GetNamespaces)

	// Serve frontend SPA
	r.mux.HandleFunc("/", SpaHandler(staticPath))
}

// ServeHTTP implements the http.Handler interface
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}
