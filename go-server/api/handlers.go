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
	"trivy-ui/kubernetes"
	"trivy-ui/utils"
)

const (
	CodeSuccess = 0
	CodeError   = 1
)

type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type PaginatedResponse struct {
	Total    int         `json:"total"`
	Page     int         `json:"page"`
	PageSize int         `json:"pageSize"`
	Data     interface{} `json:"data"`
}

type Cluster struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type Namespace struct {
	Cluster     string `json:"cluster"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type Report struct {
	Type      string      `json:"type"`
	Cluster   string      `json:"cluster"`
	Namespace string      `json:"namespace"`
	Name      string      `json:"name"`
	Status    string      `json:"status,omitempty"`
	Data      interface{} `json:"data"`
	UpdatedAt time.Time   `json:"updated_at"`
}

type Handler struct {
	cache CacheService
}

type CacheService interface {
	Get(key string) (interface{}, bool)
	Items() map[string]interface{}
	Set(key string, value interface{}, expiration time.Duration)
	Delete(key string)
}

type cacheServiceImpl struct{}

func (c *cacheServiceImpl) Get(key string) (interface{}, bool) {
	return getCache().Get(key)
}

func (c *cacheServiceImpl) Items() map[string]interface{} {
	return getCache().Items()
}

func (c *cacheServiceImpl) Set(key string, value interface{}, expiration time.Duration) {
	getCache().Set(key, value, expiration)
}

func (c *cacheServiceImpl) Delete(key string) {
	getCache().Delete(key)
}

func NewHandler(k8sClient *kubernetes.Client) *Handler {
	return &Handler{
		cache: &cacheServiceImpl{},
	}
}

func writeJSON(w http.ResponseWriter, code int, resp Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(resp)
}

func writeError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, Response{
		Code:    CodeError,
		Message: message,
	})
}

func SpaHandler(staticPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		path := filepath.Join(staticPath, r.URL.Path)
		_, err := os.Stat(path)
		if err != nil {
			http.ServeFile(w, r, filepath.Join(staticPath, "index.html"))
			return
		}
		http.ServeFile(w, r, path)
	}
}

func LoadCache() error {
	return InitCache()
}

func ReportKey(cluster, ns, typ, name string) string {
	return reportKey(cluster, ns, typ, name)
}

func (h *Handler) refreshCRDRegistry() {
	registry := config.GetGlobalRegistry()
	clients := GetAllClusterClients()
	if len(clients) > 0 {
		for _, cc := range clients {
			if cc.Client != nil && cc.Client.Config() != nil {
				if err := registry.RefreshIfNeeded(cc.Client.Config()); err != nil {
					utils.LogWarning("Failed to refresh CRDs", map[string]interface{}{"error": err.Error()})
				}
				break
			}
		}
	}
}

func (h *Handler) GetReportTypes(w http.ResponseWriter, r *http.Request) {
	h.refreshCRDRegistry()
	reportTypes := config.AllReports()
	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success",
		Data:    reportTypes,
	})
}

func (h *Handler) GetTypesV1(w http.ResponseWriter, r *http.Request) {
	h.refreshCRDRegistry()
	reportTypes := config.AllReports()
	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success",
		Data:    reportTypes,
	})
}

func (h *Handler) GetClusters(w http.ResponseWriter, r *http.Request) {
	refresh := r.URL.Query().Get("refresh") == "1"
	emptyKey := "empty:clusters"

	if !refresh {
		var clusters []Cluster
		items := h.cache.Items()
		for k, v := range items {
			if strings.HasPrefix(k, "cluster:") {
				var cluster Cluster
				switch val := v.(type) {
				case Cluster:
					cluster = val
				case map[string]interface{}:
					b, _ := json.Marshal(val)
					_ = json.Unmarshal(b, &cluster)
				default:
					continue
				}
				clusters = append(clusters, cluster)
			}
		}
		if len(clusters) > 0 {
			writeJSON(w, http.StatusOK, Response{
				Code:    CodeSuccess,
				Message: "Success (cache)",
				Data:    clusters,
			})
			return
		}
		if _, found := h.cache.Get(emptyKey); found {
			writeJSON(w, http.StatusOK, Response{
				Code:    CodeSuccess,
				Message: "Success (empty)",
				Data:    []Cluster{},
			})
			return
		}
	}

	var clusters []Cluster
	clusterClients := GetAllClusterClients()
	for name, cc := range clusterClients {
		clusterInfo := Cluster{
			Name:        name,
			Description: fmt.Sprintf("API Server: %s, version: %s", cc.APIServerURL, cc.Version),
		}
		UpsertClusterToCache(clusterInfo)
		clusters = append(clusters, clusterInfo)
	}
	if len(clusters) == 0 {
		h.cache.Set(emptyKey, true, 10*time.Second)
		writeJSON(w, http.StatusOK, Response{
			Code:    CodeSuccess,
			Message: "Success (k8s empty)",
			Data:    []Cluster{},
		})
		return
	}
	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success (k8s)",
		Data:    clusters,
	})
}

func (h *Handler) GetNamespacesByCluster(w http.ResponseWriter, r *http.Request, cluster string) {
	refresh := r.URL.Query().Get("refresh") == "1"
	emptyKey := fmt.Sprintf("empty:namespaces:%s", cluster)

	if !refresh {
		var namespaces []Namespace
		items := h.cache.Items()
		for k, v := range items {
			if strings.HasPrefix(k, "namespace:") {
				var ns Namespace
				switch val := v.(type) {
				case Namespace:
					ns = val
				case map[string]interface{}:
					b, _ := json.Marshal(val)
					_ = json.Unmarshal(b, &ns)
				default:
					continue
				}
				if ns.Cluster == cluster {
					namespaces = append(namespaces, ns)
				}
			}
		}
		if len(namespaces) > 0 {
			writeJSON(w, http.StatusOK, Response{
				Code:    CodeSuccess,
				Message: "Success (cache)",
				Data:    namespaces,
			})
			return
		}
		if _, found := h.cache.Get(emptyKey); found {
			writeJSON(w, http.StatusOK, Response{
				Code:    CodeSuccess,
				Message: "Success (empty)",
				Data:    []Namespace{},
			})
			return
		}
	}

	clusterClient := GetClusterClient(cluster)
	if clusterClient == nil {
		writeError(w, http.StatusBadRequest, "Cluster not found")
		return
	}
	nsList, err := clusterClient.Client.GetNamespaces(r.Context())
	if err != nil || len(nsList) == 0 {
		h.cache.Set(emptyKey, true, 10*time.Second)
		writeJSON(w, http.StatusOK, Response{
			Code:    CodeSuccess,
			Message: "Success (k8s empty)",
			Data:    []Namespace{},
		})
		return
	}
	var namespaces []Namespace
	for _, ns := range nsList {
		nsObj := Namespace{Cluster: cluster, Name: ns}
		UpsertNamespaceToCache(nsObj)
		namespaces = append(namespaces, nsObj)
	}
	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success (k8s)",
		Data:    namespaces,
	})
}

func (h *Handler) parseReportKey(key string) (cluster, namespace, reportType, reportName string, ok bool) {
	prefix := "report:"
	if !strings.HasPrefix(key, prefix) {
		return "", "", "", "", false
	}
	keyWithoutPrefix := strings.TrimPrefix(key, prefix)
	parts := strings.Split(keyWithoutPrefix, ":")
	if len(parts) < 4 {
		return "", "", "", "", false
	}
	cluster = parts[0]
	namespace = parts[1]
	reportType = parts[2]
	reportName = strings.Join(parts[3:], ":")
	return cluster, namespace, reportType, reportName, true
}

func (h *Handler) parseQueryParams(r *http.Request) (clusterFilter string, namespaceFilters []string, page, pageSize int) {
	clusterFilter = r.URL.Query().Get("cluster")
	namespaceParam := r.URL.Query().Get("namespace")
	if namespaceParam != "" {
		namespaceFilters = strings.Split(namespaceParam, ",")
		for i, ns := range namespaceFilters {
			namespaceFilters[i] = strings.TrimSpace(ns)
		}
	}
	page = 1
	pageSize = 50
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := r.URL.Query().Get("pageSize"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 200 {
			pageSize = parsed
		}
	}
	return clusterFilter, namespaceFilters, page, pageSize
}

func (h *Handler) getReportsFromCache(typeName, clusterFilter string, namespaceFilters []string) []Report {
	var reports []Report
	items := h.cache.Items()

	utils.LogDebug("getReportsFromCache", map[string]interface{}{
		"typeName":         typeName,
		"clusterFilter":    clusterFilter,
		"namespaceFilters": namespaceFilters,
		"total_items":      len(items),
	})

	for k, v := range items {
		cluster, namespace, reportType, reportName, ok := h.parseReportKey(k)
		if !ok {
			continue
		}
		if reportType != typeName {
			continue
		}
		if clusterFilter != "" && cluster != clusterFilter {
			continue
		}
		if len(namespaceFilters) > 0 {
			// For cluster-scoped reports (namespace is empty), always include them
			if namespace == "" {
				// Cluster-scoped report: include regardless of namespace filters
			} else {
				// Namespaced report: apply namespace filters
				hasAll := false
				matched := false
				for _, nf := range namespaceFilters {
					if nf == "all" {
						hasAll = true
						break
					}
					if namespace == nf {
						matched = true
						break
					}
				}
				if !hasAll && !matched {
					continue
				}
			}
		}

		var report Report
		switch val := v.(type) {
		case Report:
			report = val
		case map[string]interface{}:
			b, err := json.Marshal(val)
			if err != nil {
				utils.LogWarning("Failed to marshal report", map[string]interface{}{"key": k, "error": err.Error()})
				continue
			}
			if err := json.Unmarshal(b, &report); err != nil {
				utils.LogWarning("Failed to unmarshal report", map[string]interface{}{"key": k, "error": err.Error()})
				continue
			}
		default:
			utils.LogWarning("Unexpected report type", map[string]interface{}{"key": k, "type": fmt.Sprintf("%T", v)})
			continue
		}

		if report.Type == "" {
			report.Type = reportType
		}
		if report.Cluster == "" {
			report.Cluster = cluster
		}
		if report.Namespace == "" {
			report.Namespace = namespace
		}
		if report.Name == "" {
			report.Name = reportName
		}
		reports = append(reports, report)
	}

	utils.LogDebug("getReportsFromCache result", map[string]interface{}{
		"typeName": typeName,
		"count":    len(reports),
	})

	return reports
}

func (h *Handler) GetReportsByTypeV1(w http.ResponseWriter, r *http.Request, typeName string) {
	reportKind := config.GetReportByName(typeName)
	if reportKind == nil {
		writeError(w, http.StatusBadRequest, "Invalid report type")
		return
	}

	clusterFilter, namespaceFilters, page, pageSize := h.parseQueryParams(r)
	// For cluster-scoped reports, ignore namespace filters
	if reportKind != nil && !reportKind.Namespaced {
		namespaceFilters = []string{}
	}
	allReports := h.getReportsFromCache(typeName, clusterFilter, namespaceFilters)

	total := len(allReports)
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	var paginatedReports []Report
	if start < total {
		if end <= len(allReports) {
			paginatedReports = allReports[start:end]
		} else {
			paginatedReports = allReports[start:]
		}
	} else {
		paginatedReports = []Report{}
	}

	utils.LogInfo("GetReportsByTypeV1", map[string]interface{}{
		"typeName":         typeName,
		"clusterFilter":    clusterFilter,
		"namespaceFilters": namespaceFilters,
		"total":            total,
		"page":             page,
		"pageSize":         pageSize,
		"returned":         len(paginatedReports),
	})

	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success",
		Data: PaginatedResponse{
			Total:    total,
			Page:     page,
			PageSize: pageSize,
			Data:     paginatedReports,
		},
	})
}

func (h *Handler) GetReportDetailsV1(w http.ResponseWriter, r *http.Request, typeName, reportName string) {
	reportKind := config.GetReportByName(typeName)
	if reportKind == nil {
		writeError(w, http.StatusBadRequest, "Invalid report type")
		return
	}

	clusterFilter, namespaceFilters, _, _ := h.parseQueryParams(r)
	items := h.cache.Items()
	for k, v := range items {
		cluster, namespace, reportType, reportNameFromKey, ok := h.parseReportKey(k)
		if !ok {
			continue
		}
		if reportType != typeName || reportNameFromKey != reportName {
			continue
		}
		if clusterFilter != "" && cluster != clusterFilter {
			continue
		}
		if len(namespaceFilters) > 0 {
			hasAll := false
			matched := false
			for _, nf := range namespaceFilters {
				if nf == "all" {
					hasAll = true
					break
				}
				if namespace == nf {
					matched = true
					break
				}
			}
			if !hasAll && !matched {
				continue
			}
		}

		var report Report
		switch val := v.(type) {
		case Report:
			report = val
		case map[string]interface{}:
			b, err := json.Marshal(val)
			if err != nil {
				continue
			}
			if err := json.Unmarshal(b, &report); err != nil {
				continue
			}
		default:
			continue
		}

		if report.Type == "" {
			report.Type = reportType
		}
		if report.Cluster == "" {
			report.Cluster = cluster
		}
		if report.Namespace == "" {
			report.Namespace = namespace
		}
		if report.Name == "" {
			report.Name = reportNameFromKey
		}

		// Check if report data has vulnerabilities, if not fetch from Kubernetes
		hasVulnerabilities := false
		if reportData, ok := report.Data.(map[string]interface{}); ok {
			// Check if it's the full Kubernetes object structure (has "report" field with vulnerabilities)
			if reportObj, ok := reportData["report"].(map[string]interface{}); ok {
				if vulnerabilities, ok := reportObj["vulnerabilities"]; ok {
					if vulnArray, ok := vulnerabilities.([]interface{}); ok && len(vulnArray) > 0 {
						hasVulnerabilities = true
					}
				}
			} else {
				// No "report" field means it's simplified data
				// Simplified data structure: {summary: {...}, repository: "...", scanner: "..."}
				// Full data structure: {report: {vulnerabilities: [...], summary: {...}}}
				hasVulnerabilities = false
			}
		}

		if !hasVulnerabilities {
			// Fetch full report from Kubernetes
			clusterClient := GetClusterClient(cluster)
			if clusterClient != nil {
				utils.LogInfo("Fetching full report from Kubernetes", map[string]interface{}{
					"cluster":   cluster,
					"namespace": namespace,
					"type":      typeName,
					"name":      reportNameFromKey,
				})
				fullReport, err := clusterClient.Client.GetReportDetails(r.Context(), *reportKind, namespace, reportNameFromKey)
				if err == nil && fullReport != nil {
					report.Data = fullReport.Data
					report.Status = fullReport.Status
					// Update cache with full data
					UpsertReportToCache(report)
					utils.LogInfo("Fetched full report from Kubernetes", map[string]interface{}{
						"cluster":   cluster,
						"namespace": namespace,
						"type":      typeName,
						"name":      reportNameFromKey,
					})
				} else {
					utils.LogWarning("Failed to fetch full report from Kubernetes", map[string]interface{}{
						"cluster":   cluster,
						"namespace": namespace,
						"type":      typeName,
						"name":      reportNameFromKey,
						"error":     err,
					})
				}
			} else {
				utils.LogWarning("Cluster client not found", map[string]interface{}{
					"cluster": cluster,
				})
			}
		}

		writeJSON(w, http.StatusOK, Response{
			Code:    CodeSuccess,
			Message: "Success",
			Data:    report,
		})
		return
	}

	writeError(w, http.StatusNotFound, "Report not found")
}

func UpsertClusterToCache(cluster Cluster) {
	if cache != nil {
		cache.Set(clusterKey(cluster.Name), cluster, 10*time.Second)
	}
}

func UpsertNamespaceToCache(ns Namespace) {
	if cache != nil {
		cache.Set(namespaceKey(ns.Cluster, ns.Name), ns, 10*time.Second)
	}
}

func UpsertReportToCache(rep Report) {
	if cache != nil {
		cache.Set(reportKey(rep.Cluster, rep.Namespace, rep.Type, rep.Name), rep, 7*24*time.Hour)
	}
}
