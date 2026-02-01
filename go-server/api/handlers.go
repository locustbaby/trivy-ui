package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
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
	Total               int         `json:"total"`
	WithVulnerabilities int         `json:"withVulnerabilities,omitempty"`
	Page                int         `json:"page"`
	PageSize            int         `json:"pageSize"`
	Data                interface{} `json:"data"`
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
	ItemsByType(typeName string) map[string]interface{}
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

func (c *cacheServiceImpl) ItemsByType(typeName string) map[string]interface{} {
	return getCache().ItemsByType(typeName)
}

func (c *cacheServiceImpl) GetStats() map[string]interface{} {
	return getCache().GetStats()
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

// convertCacheValue 通用类型转换函数，减少重复代码
func convertCacheValue[T any](v interface{}) (T, bool) {
	var result T
	
	// 直接类型断言
	if typed, ok := v.(T); ok {
		return typed, true
	}
	
	// 通过 JSON 转换
	if mapVal, ok := v.(map[string]interface{}); ok {
		b, err := json.Marshal(mapVal)
		if err != nil {
			return result, false
		}
		if err := json.Unmarshal(b, &result); err != nil {
			return result, false
		}
		return result, true
	}
	
	return result, false
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

// ReadinessCheck 检查应用是否就绪
func (h *Handler) ReadinessCheck(w http.ResponseWriter, r *http.Request) {
	if !IsWarmupCompleted() {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("warmup not completed"))
		return
	}

	registry := config.GetGlobalRegistry()

	if !registry.IsDiscovered() {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("CRDs not discovered yet"))
		return
	}

	clients := GetAllClusterClients()
	if len(clients) == 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("No cluster clients available"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ready"))
}

// GetCacheStats 获取缓存统计信息
func (h *Handler) GetCacheStats(w http.ResponseWriter, r *http.Request) {
	stats := h.cache.(*cacheServiceImpl).GetStats()
	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success",
		Data:    stats,
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
				cluster, ok := convertCacheValue[Cluster](v)
				if !ok {
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
		h.cache.Set(emptyKey, true, 0)
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
	
	// Use a shorter timeout for namespace listing (5 seconds)
	// This prevents long waits if K8s client is not ready yet
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	
	nsList, err := clusterClient.Client.GetNamespaces(ctx)
	if err != nil {
		// Check if context was canceled or timed out
		if ctx.Err() == context.DeadlineExceeded {
			utils.LogWarning("Timeout fetching namespaces from Kubernetes", map[string]interface{}{
				"cluster": cluster,
				"error":   "timeout after 5 seconds",
			})
		} else {
			utils.LogWarning("Failed to fetch namespaces from Kubernetes", map[string]interface{}{
				"cluster": cluster,
				"error":   err.Error(),
			})
		}
		// Return empty list instead of error, so UI can still function
		writeJSON(w, http.StatusOK, Response{
			Code:    CodeSuccess,
			Message: "Success (k8s error, returning empty)",
			Data:    []Namespace{},
		})
		return
	}
	
	if len(nsList) == 0 {
		h.cache.Set(emptyKey, true, 0)
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
	items := h.cache.ItemsByType(typeName)

	utils.LogDebug("getReportsFromCache", map[string]interface{}{
		"typeName":         typeName,
		"clusterFilter":    clusterFilter,
		"namespaceFilters": namespaceFilters,
		"total_items":      len(items),
	})

	for k, v := range items {
		cluster, namespace, _, reportName, ok := h.parseReportKey(k)
		if !ok {
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
			report.Type = typeName
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

	// Sort for stable results: cluster -> namespace -> name
	sort.Slice(reports, func(i, j int) bool {
		// 1. Sort by cluster
		if reports[i].Cluster != reports[j].Cluster {
			return reports[i].Cluster < reports[j].Cluster
		}
		// 2. Sort by namespace (empty namespace goes last)
		nsI := reports[i].Namespace
		nsJ := reports[j].Namespace
		if nsI == "" && nsJ != "" {
			return false
		}
		if nsI != "" && nsJ == "" {
			return true
		}
		if nsI != nsJ {
			return nsI < nsJ
		}
		// 3. Sort by name
		return reports[i].Name < reports[j].Name
	})

	utils.LogDebug("getReportsFromCache result", map[string]interface{}{
		"typeName": typeName,
		"count":    len(reports),
	})

	return reports
}

func (h *Handler) hasVulnerabilities(report Report) bool {
	if report.Data == nil {
		return false
	}
	
	data, ok := report.Data.(map[string]interface{})
	if !ok {
		return false
	}
	
	var summary map[string]interface{}
	
	if reportObj, ok := data["report"].(map[string]interface{}); ok {
		if s, ok := reportObj["summary"].(map[string]interface{}); ok {
			summary = s
		}
	}
	
	if summary == nil {
		if s, ok := data["summary"].(map[string]interface{}); ok {
			summary = s
		}
	}
	
	if summary == nil {
		return false
	}
	
	severities := []string{"criticalCount", "highCount", "mediumCount", "lowCount"}
	for _, key := range severities {
		if count, ok := summary[key].(float64); ok && count > 0 {
			return true
		}
		if count, ok := summary[key].(int); ok && count > 0 {
			return true
		}
		if count, ok := summary[key].(int64); ok && count > 0 {
			return true
		}
	}
	
	return false
}

func (h *Handler) GetReportsByTypeV1(w http.ResponseWriter, r *http.Request, typeName string) {
	reportKind := config.GetReportByName(typeName)
	if reportKind == nil {
		writeError(w, http.StatusBadRequest, "Invalid report type")
		return
	}

	clusterFilter, namespaceFilters, page, pageSize := h.parseQueryParams(r)
	if !reportKind.Namespaced {
		namespaceFilters = []string{}
	}

	// Try to get counts from counter cache first (O(1) lookup)
	var total, withVulnerabilities int
	var countFound bool

	if len(namespaceFilters) > 0 && reportKind.Namespaced {
		// Namespace-filtered query
		total, withVulnerabilities, countFound = GetReportCountsByNamespace(clusterFilter, typeName, namespaceFilters)
	} else {
		// Cluster-level query
		total, withVulnerabilities, countFound = GetReportCounts(clusterFilter, typeName)
	}

	// Get paginated reports from cache
	allReports := h.getReportsFromCache(typeName, clusterFilter, namespaceFilters)

	// Fallback: if counter cache miss, calculate from reports
	if !countFound {
		total = len(allReports)
		withVulnerabilities = 0
		for _, report := range allReports {
			if h.hasVulnerabilities(report) {
				withVulnerabilities++
			}
		}
	}

	start := (page - 1) * pageSize
	end := start + pageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	var paginatedReports []Report
	if start < len(allReports) {
		if end <= len(allReports) {
			paginatedReports = allReports[start:end]
		} else {
			paginatedReports = allReports[start:]
		}
	} else {
		paginatedReports = []Report{}
	}

	utils.LogDebug("GetReportsByTypeV1", map[string]interface{}{
		"typeName":            typeName,
		"clusterFilter":       clusterFilter,
		"namespaceFilters":    namespaceFilters,
		"total":               total,
		"withVulnerabilities": withVulnerabilities,
		"page":                page,
		"pageSize":            pageSize,
		"returned":            len(paginatedReports),
		"countFromCache":      countFound,
	})

	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success",
		Data: PaginatedResponse{
			Total:               total,
			WithVulnerabilities: withVulnerabilities,
			Page:                page,
			PageSize:            pageSize,
			Data:                paginatedReports,
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

	var cluster, namespace string
	items := h.cache.ItemsByType(typeName)
	for k := range items {
		c, ns, _, reportNameFromKey, ok := h.parseReportKey(k)
		if !ok || reportNameFromKey != reportName {
			continue
		}
		if clusterFilter != "" && c != clusterFilter {
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
				if ns == nf {
					matched = true
					break
				}
			}
			if !hasAll && !matched {
				continue
			}
		}
		cluster = c
		namespace = ns
		break
	}

	if cluster == "" {
		writeError(w, http.StatusNotFound, "Report not found")
		return
	}

	// Check detail cache first (has full data with vulnerabilities/checks/etc)
	// Use TTL-aware getter to only trigger refresh when cache is near expiration
	if cachedDetail, found, ttlRemaining := GetReportDetailWithTTL(cluster, namespace, typeName, reportName); found {
		utils.LogDebug("Returning cached report detail", map[string]interface{}{
			"cluster":      cluster,
			"namespace":    namespace,
			"type":         typeName,
			"name":         reportName,
			"ttlRemaining": ttlRemaining.String(),
		})

		// Only trigger async refresh if TTL is less than 2 minutes
		// Since detail TTL is 5 minutes, refresh when ~40% remaining
		if ttlRemaining < 2*time.Minute {
			RefreshReportDetailAsync(cluster, namespace, typeName, reportName, *reportKind)
		}

		writeJSON(w, http.StatusOK, Response{
			Code:    CodeSuccess,
			Message: "Success",
			Data:    cachedDetail,
		})
		return
	}

	// No detail cache, fetch from Kubernetes synchronously
	clusterClient := GetClusterClient(cluster)
	if clusterClient == nil {
		writeError(w, http.StatusInternalServerError, "Cluster client not found")
		return
	}

	utils.LogDebug("Fetching full report from Kubernetes (no cache)", map[string]interface{}{
		"cluster":   cluster,
		"namespace": namespace,
		"type":      typeName,
		"name":      reportName,
	})

	fullReport, err := clusterClient.Client.GetReportDetails(r.Context(), *reportKind, namespace, reportName)
	if err != nil {
		// Check if the request was canceled by the client (context canceled)
		if r.Context().Err() == context.Canceled {
			// Client canceled the request, don't log as warning or return error
			// The client is already gone, so we can't send a response anyway
			utils.LogDebug("Request canceled by client", map[string]interface{}{
				"cluster":   cluster,
				"namespace": namespace,
				"type":      typeName,
				"name":      reportName,
			})
			return
		}
		
		utils.LogWarning("Failed to fetch report from Kubernetes", map[string]interface{}{
			"cluster":   cluster,
			"namespace": namespace,
			"type":      typeName,
			"name":      reportName,
			"error":     err.Error(),
		})
		writeError(w, http.StatusInternalServerError, "Failed to fetch report details")
		return
	}

	report := Report{
		Type:      typeName,
		Cluster:   cluster,
		Namespace: namespace,
		Name:      reportName,
		Status:    fullReport.Status,
		Data:      fullReport.Data,
		UpdatedAt: time.Now(),
	}

	// Cache the full detail for future requests
	SetReportDetail(report)

	utils.LogDebug("Fetched and cached report detail", map[string]interface{}{
		"cluster":   cluster,
		"namespace": namespace,
		"type":      typeName,
		"name":      reportName,
	})

	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success",
		Data:    report,
	})
}

func UpsertClusterToCache(cluster Cluster) {
	if cache != nil {
		cache.Set(clusterKey(cluster.Name), cluster, 0)
	}
}

func UpsertNamespaceToCache(ns Namespace) {
	if cache != nil {
		cache.Set(namespaceKey(ns.Cluster, ns.Name), ns, 0)
	}
}

func UpsertReportToCache(rep Report) {
	if cache != nil {
		cache.Set(reportKey(rep.Cluster, rep.Namespace, rep.Type, rep.Name), rep, 0)
	}
}
