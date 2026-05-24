package api

import (
	"context"
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
	Total               int         `json:"total"`
	WithVulnerabilities int         `json:"withVulnerabilities,omitempty"`
	Page                int         `json:"page"`
	PageSize            int         `json:"pageSize"`
	Data                interface{} `json:"data"`
}

type Cluster struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	SyncState   string `json:"syncState,omitempty"`
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

type SeverityTotals struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type TypeBreakdown struct {
	Scanned  int `json:"scanned"`
	Failed   int `json:"failed"`
	Critical int `json:"critical"`
}

type WorkloadSummary struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Critical  int    `json:"critical"`
	High      int    `json:"high"`
}

type ClusterSummary struct {
	Name     string `json:"name"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
}

type NamespaceSummary struct {
	Name     string `json:"name"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
}

type ClusterOverview struct {
	TotalReports           int                               `json:"total_reports"`
	SeverityTotals         SeverityTotals                    `json:"severity_totals"`
	ScanTypesBreakdown     map[string]TypeBreakdown          `json:"scan_types_breakdown"`
	TopVulnerableWorkloads []WorkloadSummary                 `json:"top_vulnerable_workloads"`
	VulnerableClusters     []ClusterSummary                  `json:"vulnerable_clusters,omitempty"`
	VulnerableNamespaces   []NamespaceSummary                `json:"vulnerable_namespaces,omitempty"`
}

type TrendRecord struct {
	Timestamp time.Time `json:"timestamp"`
	Cluster   string    `json:"cluster"`
	Critical  int       `json:"critical"`
	High      int       `json:"high"`
	Medium    int       `json:"medium"`
}

type Handler struct {
	cache      CacheService
	clusterReg *ClusterRegistry
	querySvc   QueryService
	crdReg     *config.CRDRegistry
}

type CacheService interface {
	Get(key string) (interface{}, bool)
	Items() map[string]interface{}
	ItemsByType(typeName string) map[string]interface{}
	GetReports(typeName, clusterFilter string, namespaceFilters []string) []Report
	GetReportCount(reportType, cluster string) (int, int)
	GetOverviewData(cluster string) *ClusterOverview
	Set(key string, value interface{}, expiration time.Duration)
	Delete(key string)
	DeleteReportEntry(cluster, namespace, reportType, name string)
}

type CacheServiceImpl struct {
	cache *Cache
}

func NewCacheServiceImpl() *CacheServiceImpl {
	return &CacheServiceImpl{cache: GetCache()}
}

func (c *CacheServiceImpl) getCache() *Cache {
	if c.cache == nil {
		c.cache = GetCache()
	}
	return c.cache
}

func (c *CacheServiceImpl) Get(key string) (interface{}, bool) {
	return c.getCache().Get(key)
}

func (c *CacheServiceImpl) Items() map[string]interface{} {
	return c.getCache().Items()
}

func (c *CacheServiceImpl) Set(key string, value interface{}, expiration time.Duration) {
	c.getCache().Set(key, value, expiration)
}

func (c *CacheServiceImpl) Delete(key string) {
	c.getCache().Delete(key)
}

func (c *CacheServiceImpl) DeleteReportEntry(cluster, namespace, reportType, name string) {
	c.getCache().DeleteReportEntry(cluster, namespace, reportType, name)
}

func (c *CacheServiceImpl) ItemsByType(typeName string) map[string]interface{} {
	return c.getCache().ItemsByType(typeName)
}

func (c *CacheServiceImpl) GetReports(typeName, clusterFilter string, namespaceFilters []string) []Report {
	return c.getCache().GetReports(typeName, clusterFilter, namespaceFilters)
}

func (c *CacheServiceImpl) GetReportCount(reportType, cluster string) (int, int) {
	return c.getCache().GetReportCount(reportType, cluster)
}

func (c *CacheServiceImpl) GetOverviewData(cluster string) *ClusterOverview {
	return c.getCache().GetOverviewData(cluster)
}

func (c *CacheServiceImpl) GetStats() map[string]interface{} {
	return c.getCache().GetStats()
}

func NewHandler(k8sClient *kubernetes.Client, cache CacheService, clusterReg *ClusterRegistry, querySvc QueryService, crdReg *config.CRDRegistry) *Handler {
	return &Handler{
		cache:      cache,
		clusterReg: clusterReg,
		querySvc:   querySvc,
		crdReg:     crdReg,
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
	registry := h.crdReg
	clients := h.clusterReg.All()
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
	reportTypes := h.crdReg.GetAllReports()
	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success",
		Data:    reportTypes,
	})
}

func (h *Handler) GetTypesV1(w http.ResponseWriter, r *http.Request) {
	h.refreshCRDRegistry()
	reportTypes := h.crdReg.GetAllReports()
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

	registry := h.crdReg

	if !registry.IsDiscovered() {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("CRDs not discovered yet"))
		return
	}

	clients := h.clusterReg.All()
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
	stats := h.cache.(*CacheServiceImpl).GetStats()
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
				if cc := h.clusterReg.Get(cluster.Name); cc != nil {
					cc.mu.RLock()
					cluster.SyncState = cc.SyncState
					cc.mu.RUnlock()
				}
				if cluster.SyncState == "" {
					cluster.SyncState = "Cached"
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
	clusterClients := h.clusterReg.All()
	for name, cc := range clusterClients {
		cc.mu.RLock()
		syncState := cc.SyncState
		cc.mu.RUnlock()
		if syncState == "" {
			syncState = "Cached"
		}
		clusterInfo := Cluster{
			Name:        name,
			Description: fmt.Sprintf("API Server: %s, version: %s", cc.APIServerURL, cc.Version),
			SyncState:   syncState,
		}
		h.cache.Set(clusterKey(clusterInfo.Name), clusterInfo, 0)
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

	clusterClient := h.clusterReg.Get(cluster)
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
		h.cache.Set(namespaceKey(cluster, ns), nsObj, 0)
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
	return h.cache.GetReports(typeName, clusterFilter, namespaceFilters)
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
	clusterFilter, namespaceFilters, page, pageSize := h.parseQueryParams(r)

	q := ReportQuery{
		Type:       typeName,
		Cluster:    clusterFilter,
		Namespaces: namespaceFilters,
		Page:       page,
		PageSize:   pageSize,
	}

	result := h.querySvc.ListReports(q)

	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success",
		Data: PaginatedResponse{
			Total:               result.Total,
			WithVulnerabilities: result.WithVulnerabilities,
			Page:                page,
			PageSize:            pageSize,
			Data:                result.Items,
		},
	})
}

func (h *Handler) getReportDetails(w http.ResponseWriter, r *http.Request, cluster, namespace, typeName, reportName string, allowFallback bool) {
	reportKind := h.crdReg.GetReportByName(typeName)
	if reportKind == nil {
		writeError(w, http.StatusBadRequest, "Invalid report type")
		return
	}

	if cluster == "" {
		if !allowFallback {
			writeError(w, http.StatusBadRequest, "Missing cluster parameter")
			return
		}
		items := h.cache.ItemsByType(typeName)
		for k := range items {
			c, ns, _, reportNameFromKey, ok := h.parseReportKey(k)
			if !ok || reportNameFromKey != reportName {
				continue
			}
			cluster = c
			namespace = ns
			break
		}
	}

	if cluster == "" {
		writeError(w, http.StatusNotFound, "Report not found")
		return
	}

	if cachedDetail, found, ttlRemaining := GetReportDetailWithTTL(cluster, namespace, typeName, reportName); found {
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

	clusterClient := h.clusterReg.Get(cluster)
	if clusterClient == nil {
		writeError(w, http.StatusInternalServerError, "Cluster client not found")
		return
	}

	fullReport, err := clusterClient.Client.GetReportDetails(r.Context(), *reportKind, namespace, reportName)
	if err != nil {
		if r.Context().Err() == context.Canceled {
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

	SetReportDetail(report)

	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success",
		Data:    report,
	})
}

func (h *Handler) GetReportDetails(w http.ResponseWriter, r *http.Request) {
	typeName := r.URL.Query().Get("type")
	reportName := r.URL.Query().Get("name")
	cluster := r.URL.Query().Get("cluster")
	namespace := r.URL.Query().Get("namespace")

	if typeName == "" || reportName == "" {
		writeError(w, http.StatusBadRequest, "Missing type or name parameter")
		return
	}

	h.getReportDetails(w, r, cluster, namespace, typeName, reportName, false)
}

func (h *Handler) GetReportDetailsByRef(w http.ResponseWriter, r *http.Request, cluster, typeName, namespace, reportName string) {
	h.getReportDetails(w, r, cluster, namespace, typeName, reportName, false)
}

func (h *Handler) GetReportDetailsV1(w http.ResponseWriter, r *http.Request, typeName, reportName string) {
	cluster := r.URL.Query().Get("cluster")
	namespace := r.URL.Query().Get("namespace")
	h.getReportDetails(w, r, cluster, namespace, typeName, reportName, true)
}

func (h *Handler) GetOverview(w http.ResponseWriter, r *http.Request) {
	cluster := r.URL.Query().Get("cluster")
	overview := h.cache.GetOverviewData(cluster)
	writeJSON(w, http.StatusOK, Response{
		Code: CodeSuccess,
		Data: overview,
	})
}

func (h *Handler) GetOverviewTrends(w http.ResponseWriter, r *http.Request) {
	cluster := r.URL.Query().Get("cluster")
	daysStr := r.URL.Query().Get("days")
	days := 30
	if d, err := strconv.Atoi(daysStr); err == nil && d > 0 {
		days = d
	}
	// Currently cache doesn't have GetTrends method. Wait, I should add it to CacheService interface.
	// Oh, I forgot to add GetTrends to CacheService. I'll do it.
	var trends []TrendRecord
	if impl, ok := h.cache.(*CacheServiceImpl); ok {
		trends = impl.getCache().GetTrends(cluster, days)
	}
	writeJSON(w, http.StatusOK, Response{
		Code: CodeSuccess,
		Data: trends,
	})
}

func (h *Handler) GetReportsV1(w http.ResponseWriter, r *http.Request) {
	typeName := r.URL.Query().Get("type")
	if typeName == "" {
		writeError(w, http.StatusBadRequest, "Missing type parameter")
		return
	}

	clusterFilter, namespaceFilters, page, pageSize := h.parseQueryParams(r)
	search := r.URL.Query().Get("search")
	onlyVulnerable := r.URL.Query().Get("onlyVulnerable") == "true"

	q := ReportQuery{
		Type:           typeName,
		Cluster:        clusterFilter,
		Namespaces:     namespaceFilters,
		Search:         search,
		OnlyVulnerable: onlyVulnerable,
		Page:           page,
		PageSize:       pageSize,
	}

	result := h.querySvc.ListReports(q)

	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success",
		Data: PaginatedResponse{
			Total:               result.Total,
			WithVulnerabilities: result.WithVulnerabilities,
			Page:                page,
			PageSize:            pageSize,
			Data:                result.Items,
		},
	})
}
