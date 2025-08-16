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
	"trivy-ui/kubernetes"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gocache "github.com/patrickmn/go-cache"
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

// 全局 cache 实例
var cache = gocache.New(24*time.Hour, 1*time.Hour)
var cacheFile = "cache.json"

// 启动时加载本地缓存
func LoadCache() {
	if _, err := os.Stat(cacheFile); err == nil {
		data, _ := os.ReadFile(cacheFile)
		var items map[string]gocache.Item
		if err := json.Unmarshal(data, &items); err == nil {
			cache.Items() // 触发初始化
			for k, v := range items {
				// Convert int64 expiration to time.Duration
				expiration := time.Duration(v.Expiration) * time.Second
				cache.Set(k, v.Object, expiration)
			}
		}
	}
}

// 定时持久化缓存
func SaveCache() {
	data, _ := json.MarshalIndent(cache.Items(), "", "  ")
	_ = os.WriteFile(cacheFile, data, 0644)
}

func init() {
	LoadCache()
	go func() {
		for {
			SaveCache()
			time.Sleep(60 * time.Second)
		}
	}()
}

// Handler handles API requests
type Handler struct {
	k8s *kubernetes.Client
}

// NewHandler creates a new handler
func NewHandler(k8sClient *kubernetes.Client) *Handler {
	return &Handler{
		k8s: k8sClient,
	}
}

// GetReportTypes returns all available report types
// @Summary Get all report types
// @Description Returns all available Trivy report types
// @Tags reports
// @Produce json
// @Success 200 {object} Response
// @Router /api/report-types [get]
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

// 定义 Cluster/Namespace/Report 结构体

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

// 组合 key 工具
func clusterKey(name string) string          { return "cluster:" + name }
func namespaceKey(cluster, ns string) string { return fmt.Sprintf("namespace:%s:%s", cluster, ns) }
func reportKey(cluster, ns, typ, name string) string {
	return fmt.Sprintf("report:%s:%s:%s:%s", cluster, ns, typ, name)
}

// GetClusters returns all clusters
// @Summary Get all clusters
// @Description Returns all clusters (from cache or k8s)
// @Tags clusters
// @Produce json
// @Param refresh query int false "Force refresh from k8s if 1"
// @Success 200 {object} Response
// @Router /api/clusters [get]
func (h *Handler) GetClusters(w http.ResponseWriter, r *http.Request) {
	refresh := r.URL.Query().Get("refresh") == "1"
	emptyKey := "empty:clusters"

	if !refresh {
		var clusters []Cluster
		for k, v := range cache.Items() {
			if strings.HasPrefix(k, "cluster:") {
				var cluster Cluster
				switch val := v.Object.(type) {
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
		if _, found := cache.Get(emptyKey); found {
			writeJSON(w, http.StatusOK, Response{
				Code:    CodeSuccess,
				Message: "Success (empty)",
				Data:    []Cluster{},
			})
			return
		}
	}
	// 查 k8s
	var clusters []Cluster
	if Clients != nil {
		for name, k8sClient := range Clients {
			nodeList, err := k8sClient.Clientset().CoreV1().Nodes().List(r.Context(), metav1.ListOptions{})
			if err == nil {
				version := ""
				if len(nodeList.Items) > 0 {
					version = nodeList.Items[0].Status.NodeInfo.KubeletVersion
				}
				clusterInfo := Cluster{
					Name:        name,
					Description: fmt.Sprintf("%d nodes, version: %s", len(nodeList.Items), version),
				}
				UpsertClusterToCache(clusterInfo)
				clusters = append(clusters, clusterInfo)
			}
		}
	}
	if len(clusters) == 0 {
		cache.Set(emptyKey, true, 10*time.Minute)
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

// GetNamespacesByCluster returns all namespaces for a specific cluster
// @Summary Get namespaces by cluster
// @Description Returns all namespaces for a specific cluster (from cache or k8s)
// @Tags namespaces
// @Produce json
// @Param cluster path string true "Cluster name"
// @Param refresh query int false "Force refresh from k8s if 1"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Router /api/clusters/{cluster}/namespaces [get]
func (h *Handler) GetNamespacesByCluster(w http.ResponseWriter, r *http.Request, cluster string) {
	refresh := r.URL.Query().Get("refresh") == "1"
	emptyKey := fmt.Sprintf("empty:namespaces:%s", cluster)

	if !refresh {
		var namespaces []Namespace
		for k, v := range cache.Items() {
			if strings.HasPrefix(k, "namespace:") {
				var ns Namespace
				switch val := v.Object.(type) {
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
		if _, found := cache.Get(emptyKey); found {
			writeJSON(w, http.StatusOK, Response{
				Code:    CodeSuccess,
				Message: "Success (empty)",
				Data:    []Namespace{},
			})
			return
		}
	}
	// 查 k8s
	k8sClient := h.k8s
	if Clients != nil {
		if c, ok := Clients[cluster]; ok {
			k8sClient = c
		}
	}
	if k8sClient == nil {
		writeError(w, http.StatusBadRequest, "Cluster not found")
		return
	}
	nsList, err := k8sClient.GetNamespaces(r.Context())
	if err != nil || len(nsList) == 0 {
		cache.Set(emptyKey, true, 10*time.Minute)
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

// GetReport returns a specific report
// @Summary Get a specific report
// @Description Returns a specific report by type, cluster, namespace, and name
// @Tags reports
// @Produce json
// @Param type path string true "Report type"
// @Param cluster path string true "Cluster name"
// @Param namespace path string true "Namespace"
// @Param name path string true "Report name"
// @Param refresh query int false "Force refresh from k8s if 1"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 404 {object} Response
// @Router /api/reports/{type}/{cluster}/{namespace}/{name} [get]
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
	key := reportKey(cluster, namespace, reportTypeStr, name)
	refresh := r.URL.Query().Get("refresh") == "1"
	emptyKey := fmt.Sprintf("empty:report:%s:%s:%s:%s", cluster, namespace, reportTypeStr, name)

	if !refresh {
		v, found := cache.Get(key)
		if found {
			var report Report
			switch val := v.(type) {
			case Report:
				report = val
			case map[string]interface{}:
				b, _ := json.Marshal(val)
				_ = json.Unmarshal(b, &report)
			default:
				writeError(w, http.StatusInternalServerError, "Invalid report data")
				return
			}
			// 检查 Data 字段是否为完整 CRD（有 apiVersion/kind/metadata/report 字段）
			if dataMap, ok := report.Data.(map[string]interface{}); ok {
				if _, hasAPIVersion := dataMap["apiVersion"]; hasAPIVersion && dataMap["kind"] != nil && dataMap["metadata"] != nil && dataMap["report"] != nil {
					// 是完整 CRD，直接返回
					writeJSON(w, http.StatusOK, Response{
						Code:    CodeSuccess,
						Message: "Success (cache)",
						Data:    report,
					})
					return
				}
			}
			// 否则强制查 k8s
		}
		if _, found := cache.Get(emptyKey); found {
			writeError(w, http.StatusNotFound, "Report not found (empty)")
			return
		}
	}
	// 查 k8s
	k8sClient := h.k8s
	if Clients != nil {
		if c, ok := Clients[cluster]; ok {
			k8sClient = c
		}
	}
	if k8sClient == nil {
		writeError(w, http.StatusBadRequest, "Cluster not found")
		return
	}
	reportKind := config.GetReportByName(reportTypeStr)
	if reportKind == nil {
		writeError(w, http.StatusBadRequest, "Invalid report type")
		return
	}
	rep, err := k8sClient.GetReportDetails(r.Context(), *reportKind, namespace, name)
	if err != nil || rep == nil {
		cache.Set(emptyKey, true, 10*time.Minute)
		writeError(w, http.StatusNotFound, "Report not found (k8s)")
		return
	}
	report := Report{
		Type:      string(rep.Type),
		Cluster:   cluster,
		Namespace: rep.Namespace,
		Name:      rep.Name,
		Status:    rep.Status,
		Data:      rep.Data,
		UpdatedAt: time.Now(),
	}
	UpsertReportToCache(report)
	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success (k8s)",
		Data:    report,
	})
}

func UpsertClusterToCache(cluster Cluster) {
	cache.Set(clusterKey(cluster.Name), cluster, gocache.DefaultExpiration)
}

func UpsertNamespaceToCache(ns Namespace) {
	cache.Set(namespaceKey(ns.Cluster, ns.Name), ns, gocache.DefaultExpiration)
}

func UpsertReportToCache(rep Report) {
	cache.Set(reportKey(rep.Cluster, rep.Namespace, rep.Type, rep.Name), rep, gocache.DefaultExpiration)
}

// Global clients map (set by main.go)
var Clients map[string]*kubernetes.Client

// GetReportsByTypeAndCluster returns all cluster-wide reports for a specific type and cluster
// @Summary List cluster-wide reports by type and cluster
// @Description Returns all cluster-wide reports for a specific type and cluster
// @Tags reports
// @Produce json
// @Param type path string true "Report type"
// @Param cluster path string true "Cluster name"
// @Param refresh query int false "Force refresh from k8s if 1"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Router /api/reports/{type}/{cluster} [get]
func (h *Handler) GetReportsByTypeAndCluster(w http.ResponseWriter, r *http.Request, reportType, cluster string) {
	refresh := r.URL.Query().Get("refresh") == "1"
	emptyKey := fmt.Sprintf("empty:%s:%s", cluster, reportType)

	// 1. 非 refresh 时优先查缓存
	if !refresh {
		var reports []Report
		for k, v := range cache.Items() {
			if strings.HasPrefix(k, "report:") {
				var rep Report
				switch val := v.Object.(type) {
				case Report:
					rep = val
				case map[string]interface{}:
					b, _ := json.Marshal(val)
					_ = json.Unmarshal(b, &rep)
				default:
					continue
				}
				if rep.Cluster == cluster && rep.Type == reportType {
					reports = append(reports, rep)
				}
			}
		}
		if len(reports) > 0 {
			writeJSON(w, http.StatusOK, Response{
				Code:    CodeSuccess,
				Message: "Success (cache)",
				Data:    reports,
			})
			return
		}
		// 查空标记
		if _, found := cache.Get(emptyKey); found {
			writeJSON(w, http.StatusOK, Response{
				Code:    CodeSuccess,
				Message: "Success (empty)",
				Data:    []Report{},
			})
			return
		}
	}

	// 2. 查 k8s
	k8sClient := h.k8s
	if Clients != nil {
		if c, ok := Clients[cluster]; ok {
			k8sClient = c
		}
	}
	if k8sClient == nil {
		writeError(w, http.StatusBadRequest, "Cluster not found")
		return
	}
	reportKind := config.GetReportByName(reportType)
	if reportKind == nil {
		writeError(w, http.StatusBadRequest, "Invalid report type")
		return
	}
	ctx := r.Context()
	k8sReports, err := k8sClient.GetReportsByType(ctx, *reportKind, "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(k8sReports) == 0 {
		// 标记为空，下次不再查
		cache.Set(emptyKey, true, 10*time.Minute)
		writeJSON(w, http.StatusOK, Response{
			Code:    CodeSuccess,
			Message: "Success (k8s empty)",
			Data:    []Report{},
		})
		return
	}
	// 拉到数据，写入缓存
	var reports []Report
	for _, rep := range k8sReports {
		// 归一化 cluster 字段并转换为api.Report类型
		apiReport := Report{
			Type:      rep.Type,
			Cluster:   cluster,
			Namespace: rep.Namespace,
			Name:      rep.Name,
			Status:    rep.Status,
			Data:      rep.Data,
			UpdatedAt: time.Now(),
		}
		UpsertReportToCache(apiReport)
		reports = append(reports, apiReport)
	}
	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success (k8s)",
		Data:    reports,
	})
}

// GetClusterReport returns a specific cluster-wide report
// @Summary Get a specific cluster-wide report
// @Description Returns a specific cluster-wide report by type, cluster, and name
// @Tags reports
// @Produce json
// @Param type path string true "Report type"
// @Param cluster path string true "Cluster name"
// @Param name path string true "Report name"
// @Param refresh query int false "Force refresh from k8s if 1"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 404 {object} Response
// @Router /api/reports/{type}/{cluster}/{name} [get]
func (h *Handler) GetClusterReport(w http.ResponseWriter, r *http.Request, reportType, cluster, name string) {
	key := reportKey(cluster, "", reportType, name)
	refresh := r.URL.Query().Get("refresh") == "1"
	emptyKey := fmt.Sprintf("empty:report:%s:%s:%s:%s", cluster, "", reportType, name)

	if !refresh {
		v, found := cache.Get(key)
		if found {
			var report Report
			switch val := v.(type) {
			case Report:
				report = val
			case map[string]interface{}:
				b, _ := json.Marshal(val)
				_ = json.Unmarshal(b, &report)
			default:
				writeError(w, http.StatusInternalServerError, "Invalid report data")
				return
			}
			// 检查 Data 字段是否为完整 CRD（有 apiVersion/kind/metadata/report 字段）
			if dataMap, ok := report.Data.(map[string]interface{}); ok {
				if _, hasAPIVersion := dataMap["apiVersion"]; hasAPIVersion && dataMap["kind"] != nil && dataMap["metadata"] != nil && dataMap["report"] != nil {
					// 是完整 CRD，直接返回
					writeJSON(w, http.StatusOK, Response{
						Code:    CodeSuccess,
						Message: "Success (cache)",
						Data:    report,
					})
					return
				}
			}
			// 否则强制查 k8s
		}
		if _, found := cache.Get(emptyKey); found {
			writeError(w, http.StatusNotFound, "Report not found (empty)")
			return
		}
	}
	// 查 k8s
	k8sClient := h.k8s
	if Clients != nil {
		if c, ok := Clients[cluster]; ok {
			k8sClient = c
		}
	}
	if k8sClient == nil {
		writeError(w, http.StatusBadRequest, "Cluster not found")
		return
	}
	reportKind := config.GetReportByName(reportType)
	if reportKind == nil {
		writeError(w, http.StatusBadRequest, "Invalid report type")
		return
	}
	rep, err := k8sClient.GetReportDetails(r.Context(), *reportKind, "", name)
	if err != nil || rep == nil {
		cache.Set(emptyKey, true, 10*time.Minute)
		writeError(w, http.StatusNotFound, "Report not found (k8s)")
		return
	}
	report := Report{
		Type:      string(rep.Type),
		Cluster:   cluster,
		Namespace: rep.Namespace,
		Name:      rep.Name,
		Status:    rep.Status,
		Data:      rep.Data,
		UpdatedAt: time.Now(),
	}
	UpsertReportToCache(report)
	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success (k8s)",
		Data:    report,
	})
}

// GetReportsByTypeAndNamespace returns all reports for a specific type, cluster, and namespace
// @Summary List reports by type and namespace
// @Description Returns all reports for a specific type, cluster, and namespace
// @Tags reports
// @Produce json
// @Param type path string true "Report type"
// @Param cluster path string true "Cluster name"
// @Param namespace path string true "Namespace"
// @Param refresh query int false "Force refresh from k8s if 1"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Router /api/reports/{type}/{cluster}/{namespace} [get]
func (h *Handler) GetReportsByTypeAndNamespace(w http.ResponseWriter, r *http.Request, reportType, cluster, namespace string) {
	refresh := r.URL.Query().Get("refresh") == "1"
	emptyKey := fmt.Sprintf("empty:%s:%s:%s", cluster, namespace, reportType)

	// 1. 非 refresh 时优先查缓存
	if !refresh {
		var reports []Report
		for k, v := range cache.Items() {
			if strings.HasPrefix(k, "report:") {
				var rep Report
				switch val := v.Object.(type) {
				case Report:
					rep = val
				case map[string]interface{}:
					b, _ := json.Marshal(val)
					_ = json.Unmarshal(b, &rep)
				default:
					continue
				}
				if rep.Cluster == cluster && rep.Namespace == namespace && rep.Type == reportType {
					reports = append(reports, rep)
				}
			}
		}
		if len(reports) > 0 {
			writeJSON(w, http.StatusOK, Response{
				Code:    CodeSuccess,
				Message: "Success (cache)",
				Data:    reports,
			})
			return
		}
		// 查空标记
		if _, found := cache.Get(emptyKey); found {
			writeJSON(w, http.StatusOK, Response{
				Code:    CodeSuccess,
				Message: "Success (empty)",
				Data:    []Report{},
			})
			return
		}
	}

	// 2. 查 k8s
	k8sClient := h.k8s
	if Clients != nil {
		if c, ok := Clients[cluster]; ok {
			k8sClient = c
		}
	}
	if k8sClient == nil {
		writeError(w, http.StatusBadRequest, "Cluster not found")
		return
	}
	reportKind := config.GetReportByName(reportType)
	if reportKind == nil {
		writeError(w, http.StatusBadRequest, "Invalid report type")
		return
	}
	ctx := r.Context()
	k8sReports, err := k8sClient.GetReportsByType(ctx, *reportKind, namespace)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(k8sReports) == 0 {
		// 标记为空，下次不再查
		cache.Set(emptyKey, true, 10*time.Minute)
		writeJSON(w, http.StatusOK, Response{
			Code:    CodeSuccess,
			Message: "Success (k8s empty)",
			Data:    []Report{},
		})
		return
	}
	// 拉到数据，写入缓存
	var reports []Report
	for _, rep := range k8sReports {
		// 归一化 cluster 字段
		localRep := Report{
			Type:      string(rep.Type),
			Cluster:   cluster,
			Namespace: rep.Namespace,
			Name:      rep.Name,
			Status:    rep.Status,
			Data:      rep.Data,
			UpdatedAt: time.Now(),
		}
		UpsertReportToCache(localRep)
		reports = append(reports, localRep)
	}
	writeJSON(w, http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "Success (k8s)",
		Data:    reports,
	})
}
