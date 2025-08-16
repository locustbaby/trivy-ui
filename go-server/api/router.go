// Router configuration
package api

import (
	"net/http"
	"strings"

	"trivy-ui/kubernetes"

	httpSwagger "github.com/swaggo/http-swagger"
)

// isClusterWideReport checks if a report type is cluster-wide
func isClusterWideReport(reportType string) bool {
	clusterWideTypes := []string{
		"clustercompliancereports",
		"clusterconfigauditreports", 
		"clusterinfraassessmentreports",
		"clusterrbacassessmentreports",
		"clustersbomreports",
		"clustervulnerabilityreports",
	}
	for _, t := range clusterWideTypes {
		if t == reportType {
			return true
		}
	}
	return false
}

// Router handles HTTP routing
type Router struct {
	mux     *http.ServeMux
	handler *Handler
}

// NewRouter creates a new router
func NewRouter(k8sClient *kubernetes.Client, staticPath string) *Router {
	r := &Router{
		mux:     http.NewServeMux(),
		handler: NewHandler(k8sClient),
	}
	r.Setup(staticPath)
	return r
}

// Setup configures the router
func (r *Router) Setup(staticPath string) {
	// API routes

	// Report types
	// swagger:route GET /api/report-types report-types listReportTypes
	// Returns all available Trivy report types
	r.mux.HandleFunc("/api/report-types", r.handler.GetReportTypes)

	// Reports
	// swagger:route GET /api/reports/{type}/{cluster}/{namespace}/{name} reports getReport
	// Returns a specific report by type, cluster, namespace, and name
	r.mux.HandleFunc("/api/reports/", func(w http.ResponseWriter, req *http.Request) {
		parts := strings.Split(strings.TrimPrefix(req.URL.Path, "/api/reports/"), "/")
		if req.Method == http.MethodGet && len(parts) == 2 {
			// swagger:route GET /api/reports/{type}/{cluster} reports listReportsByTypeAndCluster
			// Returns all cluster-wide reports for a specific type and cluster
			reportType := parts[0]
			cluster := parts[1]
			r.handler.GetReportsByTypeAndCluster(w, req, reportType, cluster)
			return
		}
		if req.Method == http.MethodGet && len(parts) == 3 {
			// Check if this is a cluster-wide report type
			reportType := parts[0]
			cluster := parts[1]
			thirdPart := parts[2]
			
			// Check if the third part looks like a namespace (contains namespace-like patterns)
			// For cluster-wide reports, the third part is the report name
			// For namespaced reports, the third part is the namespace
			if isClusterWideReport(reportType) {
				// swagger:route GET /api/reports/{type}/{cluster}/{name} reports getClusterReport
				// Returns a specific cluster-wide report by type, cluster, and name
				r.handler.GetClusterReport(w, req, reportType, cluster, thirdPart)
			} else {
				// swagger:route GET /api/reports/{type}/{cluster}/{namespace} reports listReportsByTypeAndNamespace
				// Returns all reports for a specific type, cluster, and namespace
				r.handler.GetReportsByTypeAndNamespace(w, req, reportType, cluster, thirdPart)
			}
			return
		}
		if req.Method == http.MethodGet && len(parts) == 4 {
			r.handler.GetReport(w, req)
			return
		}
		http.NotFound(w, req)
	})

	// Clusters
	// swagger:route GET /api/clusters clusters listClusters
	// Returns all clusters
	r.mux.HandleFunc("/api/clusters", func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet {
			r.handler.GetClusters(w, req)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	// swagger:route GET /api/clusters/{cluster}/namespaces namespaces listNamespacesByCluster
	// Returns all namespaces for a specific cluster
	r.mux.HandleFunc("/api/clusters/", func(w http.ResponseWriter, req *http.Request) {
		path := strings.TrimPrefix(req.URL.Path, "/api/clusters/")
		parts := strings.Split(path, "/")
		if len(parts) == 2 && parts[1] == "namespaces" && req.Method == http.MethodGet {
			cluster := parts[0]
			r.handler.GetNamespacesByCluster(w, req, cluster)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	// Namespaces
	// 移除 GET /api/namespaces
	// r.mux.HandleFunc("/api/namespaces", r.handler.GetNamespaces)

	// Serve swagger docs (must be before catch-all)
	r.mux.Handle("/swagger/", httpSwagger.WrapHandler)

	// Serve frontend SPA
	r.mux.HandleFunc("/", SpaHandler(staticPath))
}

// ServeHTTP implements the http.Handler interface
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}
