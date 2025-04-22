// API endpoint handlers
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"trivy-ui/config"
	"trivy-ui/data"
	"trivy-ui/kubernetes"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Response codes
const (
	CodeSuccess = 0
	CodeError   = 1
)

// Response represents the standard API response format
type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, code int, resp Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(resp)
}

// writeError writes an error response
func writeError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, Response{
		Code:    CodeError,
		Message: message,
	})
}

// getIntQueryParam gets an integer query parameter
func getIntQueryParam(r *http.Request, key string, defaultValue int) int {
	value := r.URL.Query().Get(key)
	if value == "" {
		return defaultValue
	}
	intValue, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}
	return intValue
}

// filterEmptyStrings filters out empty strings from a slice
func filterEmptyStrings(slice []string) []string {
	var result []string
	for _, s := range slice {
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}

// shouldRefresh checks if a refresh operation should be performed
func (h *Handler) shouldRefresh(key string, forceRefresh bool, dataExpired bool) bool {
	// If a refresh is already in progress for this key, don't start another one
	if h.refreshLock[key] {
		return false
	}

	// If force refresh is requested, always refresh
	if forceRefresh {
		// But still respect the refresh threshold to prevent abuse
		lastRefresh, exists := h.lastRefreshTime[key]
		if exists && time.Since(lastRefresh) < h.refreshThreshold {
			return false
		}
		return true
	}

	// If data is expired, refresh
	return dataExpired
}

// SpaHandler serves the Single Page Application frontend
func SpaHandler(staticPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If the request is for an API endpoint, return 404
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}

		// Try to serve the requested file
		path := filepath.Join(staticPath, r.URL.Path)
		_, err := os.Stat(path)
		if err != nil {
			// If the file doesn't exist, serve index.html
			http.ServeFile(w, r, filepath.Join(staticPath, "index.html"))
			return
		}

		// Serve the file
		http.ServeFile(w, r, path)
	}
}

// Handler handles API requests
type Handler struct {
	repo        *data.Repository
	clusterRepo *data.ClusterRepository
	k8s         *kubernetes.Client
	// Request coalescing to reduce Kubernetes API calls
	refreshLock      map[string]bool      // Map of in-progress refresh operations
	lastRefreshTime  map[string]time.Time // Map of last refresh times
	refreshThreshold time.Duration        // Minimum time between refreshes
}

// NewHandler creates a new handler
func NewHandler(repo *data.Repository, clusterRepo *data.ClusterRepository) *Handler {
	k8sClient, err := kubernetes.NewClient("", repo.GetDB())
	if err != nil {
		fmt.Printf("Warning: Failed to create Kubernetes client: %v\n", err)
	}
	return &Handler{
		repo:             repo,
		clusterRepo:      clusterRepo,
		k8s:              k8sClient,
		refreshLock:      make(map[string]bool),
		lastRefreshTime:  make(map[string]time.Time),
		refreshThreshold: 10 * time.Second, // Minimum 10 seconds between refreshes
	}
}

// GetReportTypes returns all available report types
func (h *Handler) GetReportTypes(w http.ResponseWriter, r *http.Request) {
	var reportTypes []string
	for _, report := range config.AllReports {
		reportTypes = append(reportTypes, report.Name)
	}
	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success",
		Data:    reportTypes,
	})
}

// GetReports returns a list of reports based on query parameters
func (h *Handler) GetReports(w http.ResponseWriter, r *http.Request) {
	// Get query parameters
	reportTypeStr := r.URL.Query().Get("type")
	cluster := r.URL.Query().Get("cluster")
	namespace := r.URL.Query().Get("namespace")
	refresh := r.URL.Query().Get("refresh") == "true"

	// Create query
	query := data.ReportQuery{
		Type:       config.ReportType(reportTypeStr),
		Clusters:   []string{cluster},
		Namespaces: []string{namespace},
	}

	// Get reports from database first
	response, err := h.repo.GetReports(query)

	// Define max age for reports (30 minutes)
	maxAge := 30 * time.Minute

	// Check if data is expired
	dataExpired := false
	if response != nil && len(response.Reports) > 0 {
		// Check the first report's age as a sample
		dataExpired = h.repo.IsReportExpired(response.Reports[0], maxAge)
	}

	// Create a unique key for this request
	requestKey := fmt.Sprintf("%s-%s-%s", reportTypeStr, cluster, namespace)

	// Check if we should refresh data from Kubernetes
	shouldRefresh := h.shouldRefresh(requestKey, refresh, dataExpired) || err != nil || (response != nil && len(response.Reports) == 0)

	// If we should refresh, fetch from Kubernetes
	if shouldRefresh {
		// Set the refresh lock to prevent duplicate requests
		h.refreshLock[requestKey] = true
		defer func() {
			// Release the lock when done
			h.refreshLock[requestKey] = false
			// Update the last refresh time
			h.lastRefreshTime[requestKey] = time.Now()
		}()
		// Find the report kind
		var reportType *config.ReportKind
		for _, rt := range config.AllReports {
			if rt.Name == reportTypeStr {
				reportType = &rt
				break
			}
		}

		if reportType == nil {
			writeError(w, http.StatusBadRequest, "Invalid report type")
			return
		}

		// Get fresh data from Kubernetes for each namespace
		var allReports []unstructured.Unstructured
		for _, ns := range query.Namespaces {
			reports, err := h.k8s.ListReports(r.Context(), *reportType, ns)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			allReports = append(allReports, reports...)
		}

		// For each report, update the database with complete information
		for _, report := range allReports {
			// Extract status and summary information
			status := "Unknown"
			summary := map[string]interface{}{
				"critical": 0,
				"high":     0,
				"medium":   0,
				"low":      0,
				"unknown":  0,
			}

			// Extract status from the report
			if statusObj, ok := report.Object["status"].(map[string]interface{}); ok {
				if phase, ok := statusObj["phase"].(string); ok {
					status = phase
				}
			}

			// Extract summary information
			if reportObj, ok := report.Object["report"].(map[string]interface{}); ok {
				if summaryObj, ok := reportObj["summary"].(map[string]interface{}); ok {
					if critical, ok := summaryObj["criticalCount"].(float64); ok {
						summary["critical"] = int(critical)
					}
					if high, ok := summaryObj["highCount"].(float64); ok {
						summary["high"] = int(high)
					}
					if medium, ok := summaryObj["mediumCount"].(float64); ok {
						summary["medium"] = int(medium)
					}
					if low, ok := summaryObj["lowCount"].(float64); ok {
						summary["low"] = int(low)
					}
					if unknown, ok := summaryObj["unknownCount"].(float64); ok {
						summary["unknown"] = int(unknown)
					}
				}
			}

			// Create report structure with complete data
			reportData := &data.Report{
				Type:      query.Type,
				Cluster:   cluster,
				Namespace: report.GetNamespace(),
				Name:      report.GetName(),
				Status:    status,
				Data: map[string]interface{}{
					"metadata": map[string]interface{}{
						"name":      report.GetName(),
						"namespace": report.GetNamespace(),
						"uid":       report.GetUID(),
					},
					"summary": summary,
					"report":  report.Object["report"],
				},
			}

			// Save report information
			if err := h.repo.SaveReport(reportData); err != nil {
				fmt.Printf("Error saving report info: %v\n", err)
				continue
			}
		}
	}

	// If we already fetched from Kubernetes, no need to query the database again
	if response == nil {
		// Get reports from database
		response, err = h.repo.GetReports(query)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success",
		Data:    response,
	})
}

// GetReport returns a specific report
func (h *Handler) GetReport(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/reports/"), "/")
	if len(parts) != 4 {
		writeError(w, http.StatusBadRequest, "Invalid URL format")
		return
	}

	reportTypeStr := parts[0]
	cluster := parts[1]
	namespace := parts[2]
	name := parts[3]
	refresh := r.URL.Query().Get("refresh") == "true"

	// Try to get report from database
	report, err := h.repo.GetReport(config.ReportType(reportTypeStr), cluster, namespace, name)
	// If report not found, we'll fetch from Kubernetes
	if err != nil && err.Error() != "report not found" {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Define max age for reports (30 minutes)
	maxAge := 30 * time.Minute

	// Check if data is expired
	dataExpired := h.repo.IsReportExpired(report, maxAge)

	// Create a unique key for this request
	requestKey := fmt.Sprintf("%s-%s-%s-%s", reportTypeStr, cluster, namespace, name)

	// Check if we should refresh data from Kubernetes
	shouldRefresh := h.shouldRefresh(requestKey, refresh, dataExpired) || err != nil || report == nil

	// Fetch from Kubernetes if needed
	if shouldRefresh {
		// Set the refresh lock to prevent duplicate requests
		h.refreshLock[requestKey] = true
		defer func() {
			// Release the lock when done
			h.refreshLock[requestKey] = false
			// Update the last refresh time
			h.lastRefreshTime[requestKey] = time.Now()
		}()
		// Find the report kind
		var reportType *config.ReportKind
		for _, rt := range config.AllReports {
			if rt.Name == reportTypeStr {
				reportType = &rt
				break
			}
		}

		if reportType == nil {
			writeError(w, http.StatusBadRequest, "Invalid report type")
			return
		}

		// Get fresh data from Kubernetes
		k8sReport, err := h.k8s.GetReportDetails(r.Context(), *reportType, namespace, name)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		// If we have both old and new data, compare them
		if report != nil && k8sReport != nil {
			oldData, err := json.Marshal(report.Data)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			newData, err := json.Marshal(k8sReport.Data)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}

			// Only update if data is different
			if string(oldData) != string(newData) {
				if err := h.repo.SaveReport(k8sReport); err != nil {
					writeError(w, http.StatusInternalServerError, err.Error())
					return
				}
			}
		} else if k8sReport != nil {
			// No old data, save new data
			if err := h.repo.SaveReport(k8sReport); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
		report = k8sReport
	}

	if report == nil {
		writeError(w, http.StatusNotFound, "Report not found")
		return
	}

	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success",
		Data:    report,
	})
}

// GetClusters returns all clusters
func (h *Handler) GetClusters(w http.ResponseWriter, r *http.Request) {
	clusters, err := h.clusterRepo.GetClusters()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success",
		Data:    clusters,
	})
}

// GetNamespaces returns all namespaces for a cluster
func (h *Handler) GetNamespaces(w http.ResponseWriter, r *http.Request) {
	cluster := r.URL.Query().Get("cluster")
	if cluster == "" {
		// If no cluster specified, return all namespaces
		namespaces, err := h.clusterRepo.GetAllNamespaces()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, Response{
			Code:    CodeSuccess,
			Message: "Success",
			Data:    namespaces,
		})
		return
	}

	namespaces, err := h.clusterRepo.GetNamespaces(cluster)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success",
		Data:    namespaces,
	})
}

// SaveCluster saves a cluster
func (h *Handler) SaveCluster(w http.ResponseWriter, r *http.Request) {
	var cluster data.Cluster
	if err := json.NewDecoder(r.Body).Decode(&cluster); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	err := h.clusterRepo.SaveCluster(&cluster)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success",
		Data:    cluster,
	})
}

// DeleteCluster deletes a cluster
func (h *Handler) DeleteCluster(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/clusters/")
	if name == "" {
		writeError(w, http.StatusBadRequest, "cluster name is required")
		return
	}

	err := h.clusterRepo.DeleteCluster(name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success",
	})
}
