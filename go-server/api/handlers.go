package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"trivy-ui/auth"
	"trivy-ui/config"
	"trivy-ui/dataaccess"
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
	Error   *APIError   `json:"error,omitempty"`
}

type APIError struct {
	Type      string `json:"type"`
	RequestID string `json:"requestId,omitempty"`
}

func markDeprecated(w http.ResponseWriter, r *http.Request, canonical string) {
	if strings.HasPrefix(r.URL.Path, canonical) {
		return
	}
	w.Header().Set("Deprecation", "true")
	w.Header().Set("Sunset", time.Now().UTC().Add(180*24*time.Hour).Format(http.TimeFormat))
	w.Header().Set("Link", "<"+canonical+">; rel=\"successor-version\"")
}

type PaginatedResponse struct {
	Total               int         `json:"total"`
	WithVulnerabilities int         `json:"withVulnerabilities,omitempty"`
	Page                int         `json:"page"`
	PageSize            int         `json:"pageSize"`
	HasNext             bool        `json:"hasNext"`
	Data                interface{} `json:"data"`
}

type Cluster struct {
	Name         string    `json:"name"`
	Description  string    `json:"description,omitempty"`
	SyncState    string    `json:"syncState,omitempty"`
	ObservedAt   time.Time `json:"observedAt,omitempty"`
	Stale        bool      `json:"stale,omitempty"`
	DataComplete bool      `json:"dataComplete"`
}

type Namespace struct {
	Cluster     string `json:"cluster"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type Report struct {
	Type            string      `json:"type"`
	Cluster         string      `json:"cluster"`
	Namespace       string      `json:"namespace"`
	Name            string      `json:"name"`
	ResourceVersion string      `json:"resourceVersion,omitempty"`
	Status          string      `json:"status,omitempty"`
	Stale           bool        `json:"stale,omitempty"`
	Data            interface{} `json:"data"`
	Ref             ReportRef   `json:"ref"`
	SortKey         string      `json:"-"`
	UpdatedAt       time.Time   `json:"updated_at"`
}

type ReportRef struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	Type      string `json:"type"`
	Name      string `json:"name"`
}

type detailFlight struct {
	done   chan struct{}
	report *kubernetes.Report
	err    error
}

var detailFlights sync.Map

func getReportDetailSingleflight(ctx context.Context, key string, fetch func() (*kubernetes.Report, error)) (report *kubernetes.Report, err error) {
	flight := &detailFlight{done: make(chan struct{})}
	actual, loaded := detailFlights.LoadOrStore(key, flight)
	if loaded {
		select {
		case <-actual.(*detailFlight).done:
			return actual.(*detailFlight).report, actual.(*detailFlight).err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	// Panic-safe: the flight entry must always be removed and the done channel
	// closed, otherwise waiters block forever on this key until restart.
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("report detail fetch panicked: %v\n%s", recovered, debug.Stack())
		}
		flight.report, flight.err = report, err
		close(flight.done)
		detailFlights.Delete(key)
	}()
	report, err = fetch()
	return report, err
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
	Cluster  string `json:"cluster"`
	Name     string `json:"name"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
}

type ClusterOverview struct {
	TotalReports           int                      `json:"total_reports"`
	SeverityTotals         SeverityTotals           `json:"severity_totals"`
	ScanTypesBreakdown     map[string]TypeBreakdown `json:"scan_types_breakdown"`
	TopVulnerableWorkloads []WorkloadSummary        `json:"top_vulnerable_workloads"`
	VulnerableClusters     []ClusterSummary         `json:"vulnerable_clusters,omitempty"`
	VulnerableNamespaces   []NamespaceSummary       `json:"vulnerable_namespaces,omitempty"`
}

type TrendRecord struct {
	Timestamp time.Time `json:"timestamp"`
	Cluster   string    `json:"cluster"`
	Namespace string    `json:"namespace,omitempty"`
	Critical  int       `json:"critical"`
	High      int       `json:"high"`
	Medium    int       `json:"medium"`
}

type Handler struct {
	cache      CacheService
	clusterReg *ClusterRegistry
	querySvc   QueryService
	crdReg     *config.CRDRegistry
	auth       *auth.Service
	dataAccess *dataaccess.Policy
}

type CacheService interface {
	Get(key string) (interface{}, bool)
	Items() map[string]interface{}
	ItemsByType(typeName string) map[string]interface{}
	GetReports(typeName, clusterFilter string, namespaceFilters []string) []Report
	GetRawReportsByType(typeName, clusterFilter string, namespaceFilters []string) []Report
	GetReportsByRefs(refs []ReportRef) ([]Report, int)
	GetReportCount(reportType, cluster string) (int, int)
	GetOverviewData(cluster string) *ClusterOverview
	GetTrends(clusterFilter string, days int) []TrendRecord
	GetStats() map[string]interface{}
	Set(key string, value interface{}, expiration time.Duration)
	Delete(key string)
	DeleteReportEntry(cluster, namespace, reportType, name string)
}

type CacheServiceImpl struct {
	cache *Cache
}

type reportSummaryProvider interface {
	ReportSummaries() []Report
}

type prefixItemProvider interface {
	ItemsByPrefix(prefix string) map[string]interface{}
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

func (c *CacheServiceImpl) ItemsByPrefix(prefix string) map[string]interface{} {
	return c.getCache().ItemsByPrefix(prefix)
}

func (c *CacheServiceImpl) ReportSummaries() []Report {
	return c.getCache().ReportSummaries()
}

func (c *CacheServiceImpl) Set(key string, value interface{}, expiration time.Duration) {
	c.getCache().Set(key, value, expiration)
}

func (c *CacheServiceImpl) Delete(key string) {
	c.getCache().Delete(key)
}

func (c *CacheServiceImpl) CapacityExceeded() bool {
	return c.getCache().CapacityExceeded()
}

func (c *CacheServiceImpl) CapacityExceededFor(cluster string) bool {
	return c.getCache().CapacityExceededFor(cluster)
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

func (c *CacheServiceImpl) GetRawReportsByType(typeName, clusterFilter string, namespaceFilters []string) []Report {
	return c.getCache().GetRawReportsByType(typeName, clusterFilter, namespaceFilters)
}

func (c *CacheServiceImpl) GetReportsByRefs(refs []ReportRef) ([]Report, int) {
	return c.getCache().GetReportsByRefs(refs)
}

func (c *CacheServiceImpl) GetReportCount(reportType, cluster string) (int, int) {
	return c.getCache().GetReportCount(reportType, cluster)
}

func (c *CacheServiceImpl) GetOverviewData(cluster string) *ClusterOverview {
	return c.getCache().GetOverviewData(cluster)
}

func (c *CacheServiceImpl) GetTrends(clusterFilter string, days int) []TrendRecord {
	return c.getCache().GetTrends(clusterFilter, days)
}

func (c *CacheServiceImpl) GetStats() map[string]interface{} {
	return c.getCache().GetStats()
}

func (h *Handler) reportSummaries() []Report {
	if provider, ok := h.cache.(reportSummaryProvider); ok {
		return provider.ReportSummaries()
	}
	items := h.cache.Items()
	if provider, ok := h.cache.(prefixItemProvider); ok {
		items = provider.ItemsByPrefix("report:")
	}
	reports := make([]Report, 0, len(items))
	for key, value := range items {
		if !strings.HasPrefix(key, "report:") {
			continue
		}
		if report, ok := convertCacheValue[Report](value); ok {
			reports = append(reports, report)
		}
	}
	return reports
}

func NewHandler(k8sClient *kubernetes.Client, cache CacheService, clusterReg *ClusterRegistry, querySvc QueryService, crdReg *config.CRDRegistry, authService *auth.Service, dataPolicy *dataaccess.Policy) *Handler {
	return &Handler{
		cache:      cache,
		clusterReg: clusterReg,
		querySvc:   querySvc,
		crdReg:     crdReg,
		auth:       authService,
		dataAccess: dataPolicy,
	}
}

func writeJSON(w http.ResponseWriter, code int, resp Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(resp)
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

func (h *Handler) reportRegistry(cluster string) *config.CRDRegistry {
	if cluster != "" {
		if client := h.clusterReg.Get(cluster); client != nil && client.Registry != nil {
			return client.Registry
		}
	}
	return h.crdReg
}

func (h *Handler) reportTypes(cluster string) []config.ReportKind {
	if cluster != "" {
		registry := h.reportRegistry(cluster)
		if client := h.clusterReg.Get(cluster); client != nil && client.Client != nil && client.Client.Config() != nil {
			if err := registry.RefreshIfNeeded(client.Client.Config()); err != nil {
				utils.LogWarning("Failed to refresh Cluster report types", map[string]interface{}{"cluster": cluster, "error": err.Error()})
			}
		}
		return registry.GetAllReports()
	}

	merged := make(map[string]config.ReportKind)
	clients := h.clusterReg.All()
	clusterNames := make([]string, 0, len(clients))
	for name := range clients {
		clusterNames = append(clusterNames, name)
	}
	sort.Strings(clusterNames)
	for _, name := range clusterNames {
		client := clients[name]
		if client.Registry == nil {
			continue
		}
		for _, reportType := range client.Registry.GetAllReports() {
			if _, exists := merged[reportType.Name]; !exists {
				merged[reportType.Name] = reportType
			}
		}
	}
	if len(merged) == 0 {
		h.refreshCRDRegistry()
		return h.crdReg.GetAllReports()
	}
	result := make([]config.ReportKind, 0, len(merged))
	for _, reportType := range merged {
		result = append(result, reportType)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func (h *Handler) reportTypesForScope(cluster string, scope auth.AccessSnapshot) []config.ReportKind {
	if cluster != "" {
		if !scope.CanReadCluster(cluster) || h.clusterReg.Get(cluster) == nil {
			return []config.ReportKind{}
		}
		return h.reportTypes(cluster)
	}
	merged := make(map[string]config.ReportKind)
	clients := h.clusterReg.All()
	clusterNames := make([]string, 0, len(clients))
	for name := range clients {
		clusterNames = append(clusterNames, name)
	}
	sort.Strings(clusterNames)
	for _, name := range clusterNames {
		client := clients[name]
		if !scope.CanReadCluster(name) || client.Registry == nil {
			continue
		}
		for _, reportType := range client.Registry.GetAllReports() {
			merged[reportType.Name] = reportType
		}
	}
	result := make([]config.ReportKind, 0, len(merged))
	for _, reportType := range merged {
		result = append(result, reportType)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func (h *Handler) GetReportTypes(w http.ResponseWriter, r *http.Request) {
	markDeprecated(w, r, "/api/v1/report-types")
	reportTypes := h.reportTypesForScope(r.URL.Query().Get("cluster"), requestAuth(r).Access)
	if h.dataAccess != nil && h.dataAccess.IsRestricted() {
		filtered := reportTypes[:0]
		for _, reportType := range reportTypes {
			if reportType.Namespaced {
				filtered = append(filtered, reportType)
			}
		}
		reportTypes = filtered
	}
	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success",
		Data:    reportTypes,
	})
}

func (h *Handler) GetTypesV1(w http.ResponseWriter, r *http.Request) {
	markDeprecated(w, r, "/api/v1/report-types")
	reportTypes := h.reportTypesForScope(r.URL.Query().Get("cluster"), requestAuth(r).Access)
	if h.dataAccess != nil && h.dataAccess.IsRestricted() {
		filtered := reportTypes[:0]
		for _, reportType := range reportTypes {
			if reportType.Namespaced {
				filtered = append(filtered, reportType)
			}
		}
		reportTypes = filtered
	}
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

	clients := h.clusterReg.All()
	if len(clients) == 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("No cluster clients available"))
		return
	}

	discovered := false
	for _, client := range clients {
		if client.Registry != nil && client.Registry.IsDiscovered() {
			discovered = true
			break
		}
	}
	if !discovered && !h.crdReg.IsDiscovered() {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("CRDs not discovered yet"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ready"))
}

// GetCacheStats 获取缓存统计信息
func (h *Handler) GetCacheStats(w http.ResponseWriter, r *http.Request) {
	if h.auth != nil && h.auth.IsEnabled() {
		writeError(w, r, http.StatusForbidden, ErrAccessDenied, "cache statistics are not available in local auth mode")
		return
	}
	stats := h.cache.GetStats()
	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success",
		Data:    stats,
	})
}

func (h *Handler) GetClusters(w http.ResponseWriter, r *http.Request) {
	markDeprecated(w, r, "/api/v1/clusters")
	refresh := r.URL.Query().Get("refresh") == "1"
	emptyKey := "empty:clusters"

	var clusters []Cluster
	clusterClients := h.clusterReg.All()
	scope := requestAuth(r).Access
	for name, cc := range clusterClients {
		if !scope.CanReadCluster(name) {
			continue
		}
		cc.mu.RLock()
		syncState := cc.SyncState
		observedAt := cc.ObservedAt
		cc.mu.RUnlock()
		if syncState == "" {
			syncState = "Cached"
		}
		clusterInfo := Cluster{
			Name:         name,
			Description:  "",
			SyncState:    syncState,
			ObservedAt:   observedAt,
			DataComplete: syncState == "FullySynced" || syncState == "Cached",
		}
		h.cache.Set(clusterKey(clusterInfo.Name), clusterInfo, 0)
		clusters = append(clusters, clusterInfo)
	}

	if len(clusters) > 0 {
		writeJSON(w, http.StatusOK, Response{
			Code:    CodeSuccess,
			Message: "Success (k8s)",
			Data:    clusters,
		})
		return
	}

	if !refresh {
		items := h.cache.Items()
		if provider, ok := h.cache.(prefixItemProvider); ok {
			items = provider.ItemsByPrefix("cluster:")
		}
		for k, v := range items {
			if !strings.HasPrefix(k, "cluster:") {
				continue
			}
			cluster, ok := convertCacheValue[Cluster](v)
			if !ok {
				continue
			}
			if cluster.SyncState == "" {
				cluster.SyncState = "Cached"
			}
			cluster.Description = ""
			cluster.DataComplete = cluster.SyncState == "FullySynced" || cluster.SyncState == "Cached"
			if !scope.CanReadCluster(cluster.Name) {
				continue
			}
			clusters = append(clusters, cluster)
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

	h.cache.Set(emptyKey, true, 0)
	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success (k8s empty)",
		Data:    []Cluster{},
	})
}

func (h *Handler) GetNamespacesByCluster(w http.ResponseWriter, r *http.Request, cluster string) {
	markDeprecated(w, r, "/api/v1/clusters/"+cluster+"/namespaces")
	scope := requestAuth(r).Access
	if !scope.CanReadCluster(cluster) {
		writeJSON(w, http.StatusOK, Response{Code: CodeSuccess, Message: "Success (empty)", Data: []Namespace{}})
		return
	}
	refresh := r.URL.Query().Get("refresh") == "1"
	emptyKey := fmt.Sprintf("empty:namespaces:%s", cluster)

	if !refresh {
		var namespaces []Namespace
		items := h.cache.Items()
		if provider, ok := h.cache.(prefixItemProvider); ok {
			items = provider.ItemsByPrefix("namespace:")
		}
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
					if !scope.CanRead(ns.Cluster, ns.Name) {
						continue
					}
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
		writeError(w, r, http.StatusBadRequest, ErrValidationFailed, "Cluster not found")
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
		if !scope.CanRead(cluster, ns) {
			continue
		}
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
	markDeprecated(w, r, "/api/v1/reports?type="+url.QueryEscape(typeName))
	clusterFilter, namespaceFilters, page, pageSize := h.parseQueryParams(r)

	q := ReportQuery{
		Type:       typeName,
		Cluster:    clusterFilter,
		Namespaces: namespaceFilters,
		Page:       page,
		PageSize:   pageSize,
		Access:     requestAuth(r).Access,
	}

	result := listReports(r.Context(), h.querySvc, q)
	if result.Incomplete {
		writeError(w, r, http.StatusServiceUnavailable, ErrDataIncomplete, "report data is incomplete because cache capacity was exceeded")
		return
	}

	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success",
		Data: PaginatedResponse{
			Total:               result.Total,
			WithVulnerabilities: result.WithVulnerabilities,
			Page:                page,
			PageSize:            pageSize,
			HasNext:             page*pageSize < result.Total,
			Data:                result.Items,
		},
	})
}

func (h *Handler) getReportDetails(w http.ResponseWriter, r *http.Request, cluster, namespace, typeName, reportName string, allowFallback bool) {
	if cluster == "" {
		if !allowFallback {
			writeError(w, r, http.StatusBadRequest, ErrValidationFailed, "Missing cluster parameter")
			return
		}
		items := h.cache.ItemsByType(typeName)
		candidates := make([]string, 0, 2)
		for k := range items {
			c, ns, typ, reportNameFromKey, ok := h.parseReportKey(k)
			if !ok || typ != typeName || reportNameFromKey != reportName {
				continue
			}
			if namespace != "" && ns != namespace {
				continue
			}
			if !requestAuth(r).Access.CanRead(c, ns) {
				continue
			}
			candidates = append(candidates, c+"\x00"+ns)
		}
		if len(candidates) > 1 {
			writeError(w, r, http.StatusConflict, ErrReportAmbiguous, "report reference is ambiguous")
			return
		}
		if len(candidates) == 1 {
			parts := strings.SplitN(candidates[0], "\x00", 2)
			cluster = parts[0]
			namespace = parts[1]
		}
	}

	if cluster == "" {
		writeError(w, r, http.StatusNotFound, ErrReportNotFound, "Report not found")
		return
	}

	reportKind := h.reportRegistry(cluster).GetReportByName(typeName)
	if reportKind == nil {
		writeError(w, r, http.StatusBadRequest, ErrValidationFailed, "Invalid report type")
		return
	}
	if !requestAuth(r).Access.CanRead(cluster, namespace) {
		writeError(w, r, http.StatusForbidden, ErrAccessDenied, "report access denied")
		return
	}

	if cachedDetail, found, ttlRemaining := GetReportDetailWithTTL(cluster, namespace, typeName, reportName); found {
		cacheCurrent := false
		if cache := getCache(); cache != nil {
			if value, summaryFound := cache.Get(reportKey(cluster, namespace, typeName, reportName)); summaryFound {
				if summary, ok := decodeReportValue(value); ok {
					cacheCurrent = summary.ResourceVersion == "" || cachedDetail.ResourceVersion == summary.ResourceVersion
				}
			}
		}
		serveStale := !cachedDetail.Stale
		if cachedDetail.Stale {
			clusterClient := h.clusterReg.Get(cluster)
			if clusterClient == nil {
				serveStale = true
			} else {
				clusterClient.mu.RLock()
				syncState := clusterClient.SyncState
				clusterClient.mu.RUnlock()
				serveStale = syncState == "" || syncState == "Initializing" || syncState == "Unavailable" || syncState == "Degraded" || syncState == "SyncFailed"
			}
		}
		if cacheCurrent && serveStale {
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
		if cache := getCache(); cache != nil {
			cache.Delete(reportDetailKey(cluster, namespace, typeName, reportName))
		}
	}

	clusterClient := h.clusterReg.Get(cluster)
	if clusterClient == nil {
		writeError(w, r, http.StatusServiceUnavailable, ErrProviderUnavailable, "Cluster client unavailable")
		return
	}

	fullReport, err := getReportDetailSingleflight(r.Context(), reportDetailKey(cluster, namespace, typeName, reportName), func() (*kubernetes.Report, error) {
		return clusterClient.Client.GetReportDetails(r.Context(), *reportKind, namespace, reportName)
	})
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
		writeError(w, r, http.StatusServiceUnavailable, ErrProviderUnavailable, "Failed to fetch report details")
		return
	}

	report := Report{
		Type:            typeName,
		Cluster:         cluster,
		Namespace:       namespace,
		Name:            reportName,
		ResourceVersion: fullReport.ResourceVersion,
		Status:          fullReport.Status,
		Data:            fullReport.Data,
		UpdatedAt:       time.Now(),
	}
	report.Ref = ReportRef{Cluster: cluster, Namespace: namespace, Type: typeName, Name: reportName}

	SetReportDetail(report)

	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success",
		Data:    report,
	})
}

func (h *Handler) GetReportDetails(w http.ResponseWriter, r *http.Request) {
	markDeprecated(w, r, "/api/v1/reports")
	typeName := r.URL.Query().Get("type")
	reportName := r.URL.Query().Get("name")
	cluster := r.URL.Query().Get("cluster")
	namespace := r.URL.Query().Get("namespace")

	if typeName == "" || reportName == "" {
		writeError(w, r, http.StatusBadRequest, ErrValidationFailed, "Missing type or name parameter")
		return
	}

	h.getReportDetails(w, r, cluster, namespace, typeName, reportName, false)
}

func (h *Handler) GetReportDetailsByRef(w http.ResponseWriter, r *http.Request, cluster, typeName, namespace, reportName string) {
	h.getReportDetails(w, r, cluster, namespace, typeName, reportName, false)
}

func (h *Handler) GetReportDetailsV1(w http.ResponseWriter, r *http.Request, typeName, reportName string) {
	markDeprecated(w, r, "/api/v1/reports")
	cluster := r.URL.Query().Get("cluster")
	namespace := r.URL.Query().Get("namespace")
	h.getReportDetails(w, r, cluster, namespace, typeName, reportName, true)
}

func (h *Handler) GetOverview(w http.ResponseWriter, r *http.Request) {
	cluster := r.URL.Query().Get("cluster")
	overview := h.getOverviewForScopeCached(cluster, requestAuth(r).Access)
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
	if days > 90 {
		writeError(w, r, http.StatusBadRequest, ErrValidationFailed, "days must be between 1 and 90")
		return
	}
	trends := h.getTrendsForScope(cluster, days, requestAuth(r).Access)
	if trends == nil {
		trends = []TrendRecord{}
	}
	writeJSON(w, http.StatusOK, Response{
		Code: CodeSuccess,
		Data: trends,
	})
}

// overviewMemo caches computed overviews keyed by cluster + access scope +
// repository version. Overview is O(N) over all summaries and the dashboard
// polls it every 15s per client; the memo collapses concurrent/repeated polls
// into a single pass per cache generation. Short TTL keeps staleness bounded.
//
// Invariants:
//   - Cached *ClusterOverview values are shared across concurrent requests and
//     MUST be treated as immutable (handlers only serialize them).
//   - The cache generation relies on every summary mutation going through
//     Cache.Set/Delete (which bump typeVersions/repositoryVersion).
type overviewMemoEntry struct {
	overview  *ClusterOverview
	expiresAt time.Time
}

var overviewMemo = struct {
	mu      sync.Mutex
	entries map[string]overviewMemoEntry
}{entries: make(map[string]overviewMemoEntry)}

const (
	overviewMemoTTL      = 3 * time.Second
	overviewMemoMaxItems = 64
)

var overviewMemoFlights sync.Map

type overviewFlight struct {
	done     chan struct{}
	overview *ClusterOverview
}

func (h *Handler) emptyOverview() *ClusterOverview {
	return &ClusterOverview{
		SeverityTotals:         SeverityTotals{},
		ScanTypesBreakdown:     make(map[string]TypeBreakdown),
		TopVulnerableWorkloads: []WorkloadSummary{},
		VulnerableClusters:     []ClusterSummary{},
		VulnerableNamespaces:   []NamespaceSummary{},
	}
}

func (h *Handler) getOverviewForScopeCached(clusterFilter string, scope auth.AccessSnapshot) *ClusterOverview {
	// Unknown clusters cannot contain reports; skip both the O(N) scan and any
	// memo insertion so unvalidated query params never grow the cache.
	if clusterFilter != "" && h.clusterReg.Get(clusterFilter) == nil {
		return h.emptyOverview()
	}

	key := fmt.Sprintf("%s\x00%s\x00%d", clusterFilter, scope.Fingerprint, getTypeVersion("", ""))
	versionAtStart := getTypeVersion("", "")
	now := time.Now()
	overviewMemo.mu.Lock()
	entry, ok := overviewMemo.entries[key]
	if ok && now.After(entry.expiresAt) {
		delete(overviewMemo.entries, key)
		ok = false
	}
	overviewMemo.mu.Unlock()
	if ok {
		return entry.overview
	}

	// Singleflight: collapse concurrent misses for the same key into one scan.
	flight := &overviewFlight{done: make(chan struct{})}
	actual, loaded := overviewMemoFlights.LoadOrStore(key, flight)
	if loaded {
		leader := actual.(*overviewFlight)
		select {
		case <-leader.done:
			return leader.overview
		case <-time.After(overviewMemoTTL):
			// Leader is taking abnormally long; fall back to computing locally.
			return h.getOverviewForScope(clusterFilter, scope)
		}
	}
	var result *ClusterOverview
	defer func() {
		if recovered := recover(); recovered != nil {
			utils.LogError("overview_compute_panic_recovered", map[string]interface{}{
				"cluster": clusterFilter,
				"error":   fmt.Sprint(recovered),
				"stack":   string(debug.Stack()),
			})
			result = h.emptyOverview()
		}
		flight.overview = result
		close(flight.done)
		overviewMemoFlights.Delete(key)
	}()

	result = h.getOverviewForScope(clusterFilter, scope)

	// TOCTOU guard: only memoize if the data version did not change while the
	// O(N) scan was running.
	if getTypeVersion("", "") == versionAtStart {
		overviewMemo.mu.Lock()
		if len(overviewMemo.entries) >= overviewMemoMaxItems {
			for k, e := range overviewMemo.entries {
				if time.Now().After(e.expiresAt) {
					delete(overviewMemo.entries, k)
				}
			}
		}
		if len(overviewMemo.entries) >= overviewMemoMaxItems {
			// Best-effort memo: dropping everything is safe and simpler than an LRU.
			overviewMemo.entries = make(map[string]overviewMemoEntry)
		}
		overviewMemo.entries[key] = overviewMemoEntry{overview: result, expiresAt: time.Now().Add(overviewMemoTTL)}
		overviewMemo.mu.Unlock()
	}
	return result
}

func (h *Handler) getOverviewForScope(clusterFilter string, scope auth.AccessSnapshot) *ClusterOverview {
	overview := &ClusterOverview{
		SeverityTotals:         SeverityTotals{},
		ScanTypesBreakdown:     make(map[string]TypeBreakdown),
		TopVulnerableWorkloads: []WorkloadSummary{},
		VulnerableClusters:     []ClusterSummary{},
		VulnerableNamespaces:   []NamespaceSummary{},
	}
	workloadScores := make(map[string]*WorkloadSummary)
	nsScores := make(map[string]*NamespaceSummary)
	clusterScores := make(map[string]*ClusterSummary)
	for _, report := range h.reportSummaries() {
		if clusterFilter != "" && report.Cluster != clusterFilter || !scope.CanRead(report.Cluster, report.Namespace) {
			continue
		}
		overview.TotalReports++
		critical, high, medium, low := extractSummaryCounts(report)
		overview.SeverityTotals.Critical += critical
		overview.SeverityTotals.High += high
		overview.SeverityTotals.Medium += medium
		overview.SeverityTotals.Low += low
		breakdown := overview.ScanTypesBreakdown[report.Type]
		breakdown.Scanned++
		if critical > 0 || high > 0 || medium > 0 || low > 0 {
			breakdown.Failed++
		}
		breakdown.Critical += critical
		overview.ScanTypesBreakdown[report.Type] = breakdown
		if critical == 0 && high == 0 {
			continue
		}
		workloadKey := fmt.Sprintf("%s:%s:%s:%s", report.Cluster, report.Namespace, report.Type, report.Name)
		if workloadScores[workloadKey] == nil {
			workloadScores[workloadKey] = &WorkloadSummary{Cluster: report.Cluster, Namespace: report.Namespace, Name: report.Name, Type: report.Type}
		}
		workloadScores[workloadKey].Critical += critical
		workloadScores[workloadKey].High += high
		namespaceKey := fmt.Sprintf("%s:%s", report.Cluster, report.Namespace)
		if nsScores[namespaceKey] == nil {
			nsScores[namespaceKey] = &NamespaceSummary{Cluster: report.Cluster, Name: report.Namespace}
		}
		nsScores[namespaceKey].Critical += critical
		nsScores[namespaceKey].High += high
		if clusterScores[report.Cluster] == nil {
			clusterScores[report.Cluster] = &ClusterSummary{Name: report.Cluster}
		}
		clusterScores[report.Cluster].Critical += critical
		clusterScores[report.Cluster].High += high
	}
	for _, workload := range workloadScores {
		overview.TopVulnerableWorkloads = append(overview.TopVulnerableWorkloads, *workload)
	}
	sort.Slice(overview.TopVulnerableWorkloads, func(i, j int) bool {
		if overview.TopVulnerableWorkloads[i].Critical != overview.TopVulnerableWorkloads[j].Critical {
			return overview.TopVulnerableWorkloads[i].Critical > overview.TopVulnerableWorkloads[j].Critical
		}
		return overview.TopVulnerableWorkloads[i].High > overview.TopVulnerableWorkloads[j].High
	})
	if len(overview.TopVulnerableWorkloads) > 5 {
		overview.TopVulnerableWorkloads = overview.TopVulnerableWorkloads[:5]
	}
	if clusterFilter == "" {
		for _, cluster := range clusterScores {
			overview.VulnerableClusters = append(overview.VulnerableClusters, *cluster)
		}
	} else {
		for _, namespace := range nsScores {
			overview.VulnerableNamespaces = append(overview.VulnerableNamespaces, *namespace)
		}
	}
	sort.Slice(overview.VulnerableClusters, func(i, j int) bool {
		return overview.VulnerableClusters[i].Critical > overview.VulnerableClusters[j].Critical
	})
	sort.Slice(overview.VulnerableNamespaces, func(i, j int) bool {
		return overview.VulnerableNamespaces[i].Critical > overview.VulnerableNamespaces[j].Critical
	})
	return overview
}

func (h *Handler) getTrendsForScope(cluster string, days int, scope auth.AccessSnapshot) []TrendRecord {
	records := h.cache.GetTrends(cluster, days)
	if scope.IsUnrestricted() {
		filtered := make([]TrendRecord, 0, len(records))
		for _, record := range records {
			if record.Namespace == "" {
				filtered = append(filtered, record)
			}
		}
		return filtered
	}

	type trendKey struct {
		bucket  time.Time
		cluster string
	}
	aggregates := make(map[trendKey]TrendRecord)
	for _, record := range records {
		if record.Namespace == "" || !scope.CanRead(record.Cluster, record.Namespace) {
			continue
		}
		bucket := record.Timestamp.UTC().Truncate(time.Hour)
		key := trendKey{bucket: bucket, cluster: record.Cluster}
		aggregate := aggregates[key]
		aggregate.Timestamp = bucket
		aggregate.Cluster = record.Cluster
		aggregate.Critical += record.Critical
		aggregate.High += record.High
		aggregate.Medium += record.Medium
		aggregates[key] = aggregate
	}

	filtered := make([]TrendRecord, 0, len(aggregates))
	for _, record := range aggregates {
		filtered = append(filtered, record)
	}
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Timestamp.Before(filtered[j].Timestamp)
	})
	return filtered
}

func (h *Handler) GetReportsV1(w http.ResponseWriter, r *http.Request) {
	typeName := r.URL.Query().Get("type")
	if typeName == "" {
		writeError(w, r, http.StatusBadRequest, ErrValidationFailed, "Missing type parameter")
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
		Access:         requestAuth(r).Access,
	}

	result := listReports(r.Context(), h.querySvc, q)
	if result.Incomplete {
		writeError(w, r, http.StatusServiceUnavailable, ErrDataIncomplete, "report data is incomplete because cache capacity was exceeded")
		return
	}

	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success",
		Data: PaginatedResponse{
			Total:               result.Total,
			WithVulnerabilities: result.WithVulnerabilities,
			Page:                page,
			PageSize:            pageSize,
			HasNext:             page*pageSize < result.Total,
			Data:                result.Items,
		},
	})
}
