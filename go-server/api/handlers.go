// API endpoint handlers
package api

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"trivy-ui/cache"
	"trivy-ui/kubernetes"
)

// FetchNamespaces handles the /namespaces endpoint
func FetchNamespaces(w http.ResponseWriter, r *http.Request) {
	cacheKey := cache.NamespacesKey()
	w.Header().Set("Content-Type", "application/json")

	// Try to get from cache
	if cachedData, found := cache.Store.Get(cacheKey); found {
		w.Header().Set("X-Cache", "HIT")
		if cachedBytes, ok := cachedData.([]byte); ok {
			w.Write(cachedBytes)
			return
		}
	}
	w.Header().Set("X-Cache", "MISS")

	// Fetch from Kubernetes API
	namespaces, err := kubernetes.Clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Store in cache (namespaces rarely change)
	responseData, err := json.Marshal(namespaces)
	if err == nil {
		cache.Store.Set(cacheKey, responseData, 10*time.Minute)
	}

	w.Write(responseData)
}

// FetchVulnerabilityReports handles the /vulnerability-reports endpoint
func FetchVulnerabilityReports(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("namespace")
	if namespace == "" {
		namespace = "default"
	}

	// Add pagination parameters
	limitStr := r.URL.Query().Get("limit")
	continueToken := r.URL.Query().Get("continue")
	search := r.URL.Query().Get("search")

	limit := int64(100) // Default limit
	if limitStr != "" {
		if parsedLimit, err := strconv.ParseInt(limitStr, 10, 64); err == nil {
			limit = parsedLimit
		}
	}

	// Generate cache key
	cacheKey := cache.ReportsKey(namespace, limit, continueToken, search)
	w.Header().Set("Content-Type", "application/json")

	// Try to get from cache
	if cachedData, found := cache.Store.Get(cacheKey); found {
		w.Header().Set("X-Cache", "HIT")
		if cachedBytes, ok := cachedData.([]byte); ok {
			w.Write(cachedBytes)
			return
		}
	}
	w.Header().Set("X-Cache", "MISS")

	// Fetch from Kubernetes API with pagination
	listOptions := metav1.ListOptions{
		Limit:    limit,
		Continue: continueToken,
	}

	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "vulnerabilityreports",
	}

	reports, err := kubernetes.DynamicClient.Resource(gvr).Namespace(namespace).List(context.TODO(), listOptions)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Apply server-side filtering
	if search != "" {
		filteredItems := filterReports(reports.Items, search)
		reports.Items = filteredItems
	}

	// Cache and return response
	responseData, err := json.Marshal(reports)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cache.Store.Set(cacheKey, responseData, 2*time.Minute)
	w.Write(responseData)
}

// Filter reports by name or container name
func filterReports(items []unstructured.Unstructured, search string) []unstructured.Unstructured {
	searchLower := strings.ToLower(search)
	filtered := []unstructured.Unstructured{}

	for _, item := range items {
		nameMatches := strings.Contains(strings.ToLower(item.GetName()), searchLower)

		containerName := ""
		if labels := item.GetLabels(); labels != nil {
			if name, ok := labels["trivy-operator.container.name"]; ok {
				containerName = name
			}
		}
		containerMatches := strings.Contains(strings.ToLower(containerName), searchLower)

		if nameMatches || containerMatches {
			filtered = append(filtered, item)
		}
	}

	return filtered
}

// FetchReportDetails handles the /report-details endpoint
func FetchReportDetails(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("namespace")
	if namespace == "" {
		namespace = "default"
	}

	reportName := r.URL.Query().Get("reportName")
	if reportName == "" {
		http.Error(w, "reportName is required", http.StatusBadRequest)
		return
	}

	// Try to get from cache
	cacheKey := cache.ReportDetailsKey(namespace, reportName)
	w.Header().Set("Content-Type", "application/json")

	if cachedData, found := cache.Store.Get(cacheKey); found {
		w.Header().Set("X-Cache", "HIT")
		if cachedBytes, ok := cachedData.([]byte); ok {
			w.Write(cachedBytes)
			return
		}
	}
	w.Header().Set("X-Cache", "MISS")

	// Get from Kubernetes API
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "vulnerabilityreports",
	}

	report, err := kubernetes.DynamicClient.Resource(gvr).Namespace(namespace).Get(context.TODO(), reportName, metav1.GetOptions{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Cache and return response
	responseData, err := json.Marshal(report)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cache.Store.Set(cacheKey, responseData, 5*time.Minute)
	w.Write(responseData)
}

// FetchReportHistory handles the /report-history endpoint
func FetchReportHistory(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadFile("report_history.json")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

// SaveReportHistory persists report data to JSON file
func SaveReportHistory(report interface{}) {
	data, err := json.Marshal(report)
	if err != nil {
		log.Printf("Error marshalling report: %s", err.Error())
		return
	}
	err = ioutil.WriteFile("report_history.json", data, 0644)
	if err != nil {
		log.Printf("Error writing report history: %s", err.Error())
	}
}

// FetchClusters handles the /clusters endpoint to list all clusters
func FetchClusters(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get all clusters from cache
	clusters, err := cache.GetClusters()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return clusters as JSON
	responseData, err := json.Marshal(clusters)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(responseData)
}

// AddCluster handles the /clusters endpoint with POST method
func AddCluster(w http.ResponseWriter, r *http.Request) {
	// Only allow POST method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Parse request body
	var cluster cache.Cluster
	if err := json.NewDecoder(r.Body).Decode(&cluster); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Add cluster to cache
	if err := cache.AddCluster(cluster); err != nil {
		if err == cache.ErrClusterExists {
			http.Error(w, "Cluster with this name already exists", http.StatusConflict)
		} else {
			http.Error(w, "Failed to add cluster: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Return success response
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Cluster added successfully"})
}

// DeleteCluster handles the /clusters/{name} endpoint with DELETE method
func DeleteCluster(w http.ResponseWriter, r *http.Request) {
	// Only allow DELETE method
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Get cluster name from URL path
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 3 {
		http.Error(w, "Invalid URL path", http.StatusBadRequest)
		return
	}

	clusterName := parts[len(parts)-1]
	if clusterName == "" {
		http.Error(w, "Cluster name is required", http.StatusBadRequest)
		return
	}

	// Delete cluster from cache
	if err := cache.DeleteCluster(clusterName); err != nil {
		if err == cache.ErrClusterNotFound {
			http.Error(w, "Cluster not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to delete cluster: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Return success response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Cluster deleted successfully"})
}

// SpaHandler serves the Single Page Application frontend
func SpaHandler(staticPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip API endpoints
		if strings.HasPrefix(r.URL.Path, "/namespaces") ||
			strings.HasPrefix(r.URL.Path, "/vulnerability-reports") ||
			strings.HasPrefix(r.URL.Path, "/report-details") ||
			strings.HasPrefix(r.URL.Path, "/report-history") ||
			strings.HasPrefix(r.URL.Path, "/clusters") {
			return
		}

		path := filepath.Join(staticPath, r.URL.Path)
		_, err := os.Stat(path)

		if os.IsNotExist(err) || r.URL.Path == "/" {
			http.ServeFile(w, r, filepath.Join(staticPath, "index.html"))
			return
		} else if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.FileServer(http.Dir(staticPath)).ServeHTTP(w, r)
	}
}
