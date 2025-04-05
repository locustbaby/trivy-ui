// API endpoint handlers
package api

import (
	"context"
	"encoding/json"
	"fmt"
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
	"k8s.io/client-go/dynamic"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"trivy-ui/cache"
	"trivy-ui/kubernetes"
)

// Response codes
const (
	CodeSuccess          = 0
	CodeInvalidRequest   = 11
	CodeNotFound         = 12
	CodeAlreadyExists    = 13
	CodeInternalError    = 14
	CodeMethodNotAllowed = 15
)

// Response represents a standard API response
type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// writeJSON writes a JSON response with the given code, message and data
func writeJSON(w http.ResponseWriter, code int, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{
		Code:    code,
		Message: message,
		Data:    data,
	})
}

// writeError writes an error response
func writeError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, message, nil)
}

// FetchNamespaces handles the /namespaces endpoint
func FetchNamespaces(w http.ResponseWriter, r *http.Request) {
	// Get cluster parameter
	cluster := r.URL.Query().Get("cluster")
	if cluster == "" {
		http.Error(w, "Cluster parameter is required", http.StatusBadRequest)
		return
	}

	// Get cluster configuration
	clusterObj, err := kubernetes.GetCluster(cluster)
	if err != nil {
		http.Error(w, "Cluster not found: "+err.Error(), http.StatusNotFound)
		return
	}

	// Create a new Kubernetes client for this cluster
	config, err := clientcmd.BuildConfigFromFlags("", clusterObj.KubeConfig)
	if err != nil {
		http.Error(w, "Error building kubeconfig: "+err.Error(), http.StatusInternalServerError)
		return
	}

	clientset, err := k8s.NewForConfig(config)
	if err != nil {
		http.Error(w, "Error creating Kubernetes client: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Generate cache key
	cacheKey := cache.NamespacesKey(cluster)
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
	namespaces, err := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
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

	// Get cluster parameter
	cluster := r.URL.Query().Get("cluster")
	if cluster == "" {
		http.Error(w, "Cluster parameter is required", http.StatusBadRequest)
		return
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
	cacheKey := cache.ReportsKey(cluster+"_"+namespace, limit, continueToken, search)
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

	// Get cluster configuration
	clusterObj, err := kubernetes.GetCluster(cluster)
	if err != nil {
		http.Error(w, "Cluster not found: "+err.Error(), http.StatusNotFound)
		return
	}

	// Create a new Kubernetes client for this cluster
	config, err := clientcmd.BuildConfigFromFlags("", clusterObj.KubeConfig)
	if err != nil {
		http.Error(w, "Error building kubeconfig: "+err.Error(), http.StatusInternalServerError)
		return
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		http.Error(w, "Error creating dynamic client: "+err.Error(), http.StatusInternalServerError)
		return
	}

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

	reports, err := dynamicClient.Resource(gvr).Namespace(namespace).List(context.TODO(), listOptions)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Apply server-side filtering
	if search != "" {
		filteredItems := filterReports(reports.Items, search)
		reports.Items = filteredItems
	}

	// Add cluster label to each report
	for i := range reports.Items {
		labels := reports.Items[i].GetLabels()
		if labels == nil {
			labels = make(map[string]string)
		}
		labels["trivy-operator.cluster"] = cluster
		reports.Items[i].SetLabels(labels)
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
		http.Error(w, "Namespace parameter is required", http.StatusBadRequest)
		return
	}

	reportName := r.URL.Query().Get("reportName")
	if reportName == "" {
		http.Error(w, "Report name parameter is required", http.StatusBadRequest)
		return
	}

	// Get cluster parameter
	cluster := r.URL.Query().Get("cluster")
	if cluster == "" {
		http.Error(w, "Cluster parameter is required", http.StatusBadRequest)
		return
	}

	// Generate cache key
	cacheKey := cache.ReportDetailsKey(cluster+"_"+namespace, reportName)
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

	// Get cluster configuration
	clusterObj, err := kubernetes.GetCluster(cluster)
	if err != nil {
		http.Error(w, "Cluster not found: "+err.Error(), http.StatusNotFound)
		return
	}

	// Create a new Kubernetes client for this cluster
	config, err := clientcmd.BuildConfigFromFlags("", clusterObj.KubeConfig)
	if err != nil {
		http.Error(w, "Error building kubeconfig: "+err.Error(), http.StatusInternalServerError)
		return
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		http.Error(w, "Error creating dynamic client: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Fetch from Kubernetes API
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "vulnerabilityreports",
	}

	report, err := dynamicClient.Resource(gvr).Namespace(namespace).Get(context.TODO(), reportName, metav1.GetOptions{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Add cluster label to report
	labels := report.GetLabels()
	if labels == nil {
		labels = make(map[string]string)
	}
	labels["trivy-operator.cluster"] = cluster
	report.SetLabels(labels)

	// Cache and return response
	responseData, err := json.Marshal(report)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cache.Store.Set(cacheKey, responseData, 2*time.Minute)
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

	clusters, err := kubernetes.GetClusters()
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
	var cluster kubernetes.Cluster
	if err := json.NewDecoder(r.Body).Decode(&cluster); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Add cluster to cache
	if err := kubernetes.AddCluster(cluster); err != nil {
		if err == kubernetes.ErrClusterExists {
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
	clusterName := strings.TrimPrefix(r.URL.Path, "/clusters/")
	if clusterName == "" {
		http.Error(w, "Cluster name is required", http.StatusBadRequest)
		return
	}

	// Delete cluster from cache
	if err := kubernetes.DeleteCluster(clusterName); err != nil {
		if err == kubernetes.ErrClusterNotFound {
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

// UpdateCluster handles the /clusters/{name} endpoint with PUT method
func UpdateCluster(w http.ResponseWriter, r *http.Request) {
	// Only allow PUT method
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Get cluster name from URL path
	clusterName := strings.TrimPrefix(r.URL.Path, "/clusters/")
	if clusterName == "" {
		http.Error(w, "Cluster name is required", http.StatusBadRequest)
		return
	}

	// Parse request body
	var cluster kubernetes.Cluster
	if err := json.NewDecoder(r.Body).Decode(&cluster); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Log the request data for debugging
	kubeConfigStatus := "missing"
	if cluster.KubeConfig != "" {
		kubeConfigStatus = "present"
	}
	log.Printf("Update cluster request: name=%s, kubeConfig=%s, enable=%v",
		cluster.Name,
		kubeConfigStatus,
		cluster.Enable)

	// Validate cluster name matches URL
	if cluster.Name != clusterName {
		http.Error(w, "Cluster name in URL does not match request body", http.StatusBadRequest)
		return
	}

	// Update cluster in cache
	if err := kubernetes.UpdateCluster(cluster); err != nil {
		if err == kubernetes.ErrClusterNotFound {
			http.Error(w, "Cluster not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to update cluster: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Return success response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Cluster updated successfully"})
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

func CreateCluster(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, CodeMethodNotAllowed, "Method not allowed")
		return
	}

	var cluster kubernetes.Cluster
	if err := json.NewDecoder(r.Body).Decode(&cluster); err != nil {
		writeError(w, CodeInvalidRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}

	// Validate cluster data
	if cluster.Name == "" {
		writeError(w, CodeInvalidRequest, "Cluster name is required")
		return
	}
	if cluster.KubeConfig == "" {
		writeError(w, CodeInvalidRequest, "KubeConfig is required")
		return
	}

	// Check if cluster already exists
	clusters, err := kubernetes.GetClusters()
	if err != nil {
		writeError(w, CodeInternalError, fmt.Sprintf("Failed to load clusters: %v", err))
		return
	}

	for _, c := range clusters {
		if c.Name == cluster.Name {
			writeError(w, CodeAlreadyExists, fmt.Sprintf("Cluster '%s' already exists", cluster.Name))
			return
		}
	}

	// Set default enable status
	cluster.Enable = true

	// Add the new cluster
	clusters = append(clusters, cluster)
	if err := kubernetes.SaveClusters(clusters); err != nil {
		writeError(w, CodeInternalError, fmt.Sprintf("Failed to save cluster: %v", err))
		return
	}

	// Return success response with cluster data
	writeJSON(w, CodeSuccess, "Cluster created successfully", cluster)
}
