package api

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"trivy-ui/config"
	"trivy-ui/kubernetes"
	"trivy-ui/utils"

	"github.com/dgraph-io/ristretto"
)

var globalCache *Cache
var cache *Cache

// Track ongoing async refreshes to prevent duplicate refreshes
var refreshInProgress sync.Map // map[string]bool, key is reportDetailKey

// reportCounts stores atomic counters for report totals and vulnerability counts
// Key format: "count:<cluster>:<type>" or "count:<cluster>:<ns>:<type>"
type reportCounters struct {
	mu     sync.RWMutex
	counts map[string]*counterPair
}

type counterPair struct {
	total    int
	withVuln int
}

var counters = &reportCounters{
	counts: make(map[string]*counterPair),
}

type CacheItem struct {
	Value      interface{} `json:"value"`
	Expiration int64       `json:"expiration"`
}

type Cache struct {
	cache      *ristretto.Cache
	mu         sync.RWMutex
	cacheFile  string
	items      map[string]CacheItem
	reportKeys map[string]bool
	keyMap     map[uint64]string
	typeIndex  map[string]map[string]bool
}

func InitCache() error {
	cfg := config.Get()
	cacheFilePath := "cache.json"
	if cfg.DataPath != "" && cfg.DataPath != "." {
		cacheFilePath = filepath.Join(cfg.DataPath, "cache.json")
	}
	
	globalCache = &Cache{
		cacheFile:  cacheFilePath,
		items:      make(map[string]CacheItem),
		reportKeys: make(map[string]bool),
		keyMap:     make(map[uint64]string),
		typeIndex:  make(map[string]map[string]bool),
	}

	config := &ristretto.Config{
		NumCounters: 1e7,
		MaxCost:     1 << 30,
		BufferItems: 64,
		OnEvict: func(item *ristretto.Item) {
			if globalCache != nil {
				globalCache.mu.Lock()
				if keyStr, ok := globalCache.keyMap[item.Key]; ok {
					delete(globalCache.items, keyStr)
					if strings.HasPrefix(keyStr, "report:") {
						delete(globalCache.reportKeys, keyStr)
						if typ := reportTypeFromKey(keyStr); typ != "" {
							if idx, ok := globalCache.typeIndex[typ]; ok {
								delete(idx, keyStr)
							}
						}
					}
					delete(globalCache.keyMap, item.Key)
				}
				globalCache.mu.Unlock()
			}
		},
	}
	ristrettoCache, err := ristretto.NewCache(config)
	if err != nil {
		return fmt.Errorf("failed to create cache: %w", err)
	}

	globalCache.cache = ristrettoCache

	if err := globalCache.LoadFromFile(); err != nil {
		utils.LogWarning("Failed to load cache from file", map[string]interface{}{"error": err.Error()})
	}

	go globalCache.periodicSave()

	return nil
}

func GetCache() *Cache {
	if globalCache == nil {
		if err := InitCache(); err != nil {
			utils.LogError("Failed to initialize cache", map[string]interface{}{"error": err.Error()})
			return nil
		}
	}
	return globalCache
}

func (c *Cache) Get(key string) (interface{}, bool) {
	// First try ristretto cache
	if value, found := c.cache.Get(key); found {
		return value, true
	}
	// Fallback to items map
	c.mu.RLock()
	defer c.mu.RUnlock()
	if item, found := c.items[key]; found {
		now := time.Now().Unix()
		if strings.HasPrefix(key, "report:") || item.Expiration > now {
			return item.Value, true
		}
	}
	return nil, false
}

func (c *Cache) Set(key string, value interface{}, expiration time.Duration) {
	cost := int64(len(key)) + estimateSize(value)
	isReport := strings.HasPrefix(key, "report:")
	if expiration <= 0 {
		if isReport {
			expiration = 7 * 24 * time.Hour
		} else {
			expiration = 10 * time.Second
		}
	}
	keyHash := c.hashKey(key)
	c.cache.SetWithTTL(key, value, cost, expiration)
	c.mu.Lock()
	c.keyMap[keyHash] = key
	c.items[key] = CacheItem{
		Value:      value,
		Expiration: time.Now().Add(expiration).Unix(),
	}
	if isReport {
		c.reportKeys[key] = true
		if typ := reportTypeFromKey(key); typ != "" {
			if c.typeIndex[typ] == nil {
				c.typeIndex[typ] = make(map[string]bool)
			}
			c.typeIndex[typ][key] = true
		}
	}
	c.mu.Unlock()
}

func (c *Cache) Delete(key string) {
	keyHash := c.hashKey(key)
	c.cache.Del(key)
	c.mu.Lock()
	delete(c.items, key)
	delete(c.keyMap, keyHash)
	if strings.HasPrefix(key, "report:") {
		delete(c.reportKeys, key)
		if typ := reportTypeFromKey(key); typ != "" {
			if idx, ok := c.typeIndex[typ]; ok {
				delete(idx, key)
			}
		}
	}
	c.mu.Unlock()
}

func (c *Cache) Items() map[string]interface{} {
	c.mu.RLock()
	itemsCopy := make(map[string]CacheItem, len(c.items))
	reportKeysCopy := make(map[string]bool, len(c.reportKeys))
	for k, v := range c.items {
		itemsCopy[k] = v
	}
	for k := range c.reportKeys {
		reportKeysCopy[k] = true
	}
	c.mu.RUnlock()

	now := time.Now().Unix()
	result := make(map[string]interface{}, len(itemsCopy))

	// First, try to get from ristretto cache (most up-to-date)
	// Then fallback to items map
	for k, item := range itemsCopy {
		var value interface{}
		found := false

		// Try ristretto first
		if val, ok := c.cache.Get(k); ok {
			value = val
			found = true
		} else {
			// Fallback to items map
			value = item.Value
			found = true
		}

		if found {
			if strings.HasPrefix(k, "report:") {
				result[k] = value
			} else if item.Expiration > now {
				result[k] = value
			}
		}
	}

	// Also check reportKeys that might be in ristretto but not in items yet
	for k := range reportKeysCopy {
		if _, exists := result[k]; !exists {
			if val, found := c.cache.Get(k); found {
				result[k] = val
			}
		}
	}

	return result
}

func (c *Cache) ItemsByType(typeName string) map[string]interface{} {
	c.mu.RLock()
	keys := make([]string, 0)
	if idx, ok := c.typeIndex[typeName]; ok {
		for k := range idx {
			keys = append(keys, k)
		}
	}
	c.mu.RUnlock()

	result := make(map[string]interface{}, len(keys))
	for _, k := range keys {
		if val, ok := c.Get(k); ok {
			result[k] = val
		}
	}
	return result
}

func (c *Cache) GetReportCount(reportType, cluster string) (total int, withVulnerabilities int) {
	items := c.Items()
	
	for k, v := range items {
		if !strings.HasPrefix(k, "report:") {
			continue
		}
		parts := strings.SplitN(strings.TrimPrefix(k, "report:"), ":", 4)
		if len(parts) < 4 {
			continue
		}
		itemCluster := parts[0]
		itemType := parts[2]

		if reportType != "" && itemType != reportType {
			continue
		}
		if cluster != "" && itemCluster != cluster {
			continue
		}

		total++

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

		if hasVulnerabilitiesInReport(report) {
			withVulnerabilities++
		}
	}
	return
}

// hasVulnerabilitiesInReport checks if a report has any vulnerabilities
func hasVulnerabilitiesInReport(report Report) bool {
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

func (c *Cache) GetStats() map[string]interface{} {
	c.mu.RLock()
	itemCount := len(c.items)
	reportCount := len(c.reportKeys)
	c.mu.RUnlock()

	return map[string]interface{}{
		"total_items":  itemCount,
		"report_items": reportCount,
	}
}

func (c *Cache) HasCacheData() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.reportKeys) > 0 || len(c.items) > 0
}

func (c *Cache) LoadFromFile() error {
	if _, err := os.Stat(c.cacheFile); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(c.cacheFile)
	if err != nil {
		return fmt.Errorf("failed to read cache file: %w", err)
	}

	var items map[string]CacheItem
	if err := json.Unmarshal(data, &items); err != nil {
		return fmt.Errorf("failed to unmarshal cache data: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Reset counters before rebuilding from cache
	ResetReportCounts()

	now := time.Now().Unix()
	for k, item := range items {
		isReport := strings.HasPrefix(k, "report:")
		if item.Expiration > now {
			expiration := time.Duration(item.Expiration-now) * time.Second
			if isReport && expiration < 24*time.Hour {
				expiration = 7 * 24 * time.Hour
			}
			cost := int64(len(k)) + estimateSize(item.Value)
			c.cache.SetWithTTL(k, item.Value, cost, expiration)
			if isReport {
				c.items[k] = CacheItem{
					Value:      item.Value,
					Expiration: time.Now().Add(expiration).Unix(),
				}
				c.reportKeys[k] = true
				if typ := reportTypeFromKey(k); typ != "" {
					if c.typeIndex[typ] == nil {
						c.typeIndex[typ] = make(map[string]bool)
					}
					c.typeIndex[typ][k] = true
				}
				c.updateCountersFromReportKey(k, item.Value)
			} else {
				c.items[k] = item
			}
		} else if isReport {
			if val, found := c.cache.Get(k); found {
				cost := int64(len(k)) + estimateSize(val)
				c.cache.SetWithTTL(k, val, cost, 7*24*time.Hour)
				c.items[k] = CacheItem{
					Value:      val,
					Expiration: time.Now().Add(7 * 24 * time.Hour).Unix(),
				}
				c.reportKeys[k] = true
				if typ := reportTypeFromKey(k); typ != "" {
					if c.typeIndex[typ] == nil {
						c.typeIndex[typ] = make(map[string]bool)
					}
					c.typeIndex[typ][k] = true
				}
				c.updateCountersFromReportKey(k, val)
			}
		}
	}

	return nil
}

// updateCountersFromReportKey parses a report key and updates counters
// Key format: "report:<cluster>:<namespace>:<type>:<name>"
func (c *Cache) updateCountersFromReportKey(key string, value interface{}) {
	parts := strings.SplitN(key, ":", 5)
	if len(parts) < 5 {
		return
	}
	cluster := parts[1]
	namespace := parts[2]
	reportType := parts[3]

	// Check if report has vulnerabilities
	hasVuln := false
	if report, ok := value.(Report); ok {
		hasVuln = hasVulnerabilitiesInReport(report)
	} else if reportMap, ok := value.(map[string]interface{}); ok {
		// Convert map to Report struct for vulnerability check
		report := Report{Data: reportMap["data"]}
		hasVuln = hasVulnerabilitiesInReport(report)
	}

	// Increment counters (don't hold cache mutex - use counter's own mutex)
	IncrementReportCount(cluster, namespace, reportType, hasVuln)
}

func (c *Cache) SaveToFile() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now().Unix()
	validItems := make(map[string]CacheItem)
	for k, item := range c.items {
		if item.Expiration > now {
			validItems[k] = item
		}
	}

	data, err := json.MarshalIndent(validItems, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cache data: %w", err)
	}

	if err := os.WriteFile(c.cacheFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	return nil
}

func getCache() *Cache {
	if cache == nil {
		cache = GetCache()
	}
	return cache
}

func clusterKey(name string) string {
	return "cluster:" + name
}

func namespaceKey(cluster, ns string) string {
	return fmt.Sprintf("namespace:%s:%s", cluster, ns)
}

func reportKey(cluster, ns, typ, name string) string {
	return fmt.Sprintf("report:%s:%s:%s:%s", cluster, ns, typ, name)
}

func reportTypeFromKey(key string) string {
	if !strings.HasPrefix(key, "report:") {
		return ""
	}
	parts := strings.SplitN(key[7:], ":", 4)
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

func (c *Cache) hashKey(key string) uint64 {
	var hash uint64
	for _, b := range []byte(key) {
		hash = hash*31 + uint64(b)
	}
	return hash
}

func estimateSize(value interface{}) int64 {
	if value == nil {
		return 8
	}
	switch v := value.(type) {
	case string:
		return int64(len(v))
	case []byte:
		return int64(len(v))
	case int, int8, int16, int32, int64:
		return 8
	case uint, uint8, uint16, uint32, uint64:
		return 8
	case float32, float64:
		return 8
	case bool:
		return 1
	case []interface{}:
		size := int64(24)
		for _, item := range v {
			size += estimateSize(item)
		}
		return size
	case map[string]interface{}:
		size := int64(8)
		for k, v := range v {
			size += int64(len(k)) + estimateSize(v)
		}
		return size
	}
	data, err := json.Marshal(value)
	if err != nil {
		return 1024
	}
	return int64(len(data))
}

func (c *Cache) periodicSave() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if err := c.SaveToFile(); err != nil {
			utils.LogWarning("Failed to save cache", map[string]interface{}{"error": err.Error()})
		}
	}
}

func (c *Cache) ValidateAndCleanup(ctx context.Context) {
	utils.LogInfo("Starting cache validation and cleanup")
	
	c.mu.RLock()
	reportKeysCopy := make([]string, 0, len(c.reportKeys))
	for k := range c.reportKeys {
		reportKeysCopy = append(reportKeysCopy, k)
	}
	c.mu.RUnlock()

	if len(reportKeysCopy) == 0 {
		utils.LogInfo("No cache data to validate")
		return
	}

	clients := GetAllClusterClients()
	if len(clients) == 0 {
		utils.LogInfo("No cluster clients available, skipping cache validation")
		return
	}

	registry := config.GetGlobalRegistry()
	reports := registry.GetAllReports()
	if len(reports) == 0 {
		utils.LogInfo("No report types discovered, skipping cache validation")
		return
	}

	reportTypesByName := make(map[string]*config.ReportKind)
	for i := range reports {
		reportTypesByName[reports[i].Name] = &reports[i]
	}

	clusterReports := make(map[string]map[string]bool)
	for _, key := range reportKeysCopy {
		if !strings.HasPrefix(key, "report:") {
			continue
		}
		parts := strings.SplitN(strings.TrimPrefix(key, "report:"), ":", 4)
		if len(parts) < 4 {
			continue
		}
		cluster := parts[0]
		namespace := parts[1]
		reportType := parts[2]
		name := parts[3]

		if clusterReports[cluster] == nil {
			clusterReports[cluster] = make(map[string]bool)
		}
		clusterReports[cluster][fmt.Sprintf("%s:%s:%s", namespace, reportType, name)] = true
	}

	const batchSize = 50
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 3)

	for clusterName, clusterClient := range clients {
		expectedReports := clusterReports[clusterName]
		if len(expectedReports) == 0 {
			continue
		}

		reportKeysList := make([]string, 0, len(expectedReports))
		for k := range expectedReports {
			reportKeysList = append(reportKeysList, k)
		}

		for i := 0; i < len(reportKeysList); i += batchSize {
			end := i + batchSize
			if end > len(reportKeysList) {
				end = len(reportKeysList)
			}
			batch := reportKeysList[i:end]

			wg.Add(1)
			semaphore <- struct{}{}
			go func(name string, cc *ClusterClient, batch []string) {
				defer wg.Done()
				defer func() { <-semaphore }()

				select {
				case <-ctx.Done():
					return
				default:
				}

				informerManager := cc.Client.GetInformer()
				if informerManager == nil {
					return
				}

				informers := informerManager.GetAllInformers()
				if len(informers) == 0 {
					return
				}

				for _, key := range batch {
					select {
					case <-ctx.Done():
						return
					default:
					}

					parts := strings.SplitN(key, ":", 3)
					if len(parts) < 3 {
						continue
					}
					ns := parts[0]
					typ := parts[1]
					repName := parts[2]

					reportKind, ok := reportTypesByName[typ]
					if !ok {
						continue
					}

					informer, hasInformer := informers[typ]
					if !hasInformer {
						continue
					}

					store := informer.GetStore()
					storeKey := fmt.Sprintf("%s/%s", ns, repName)
					if reportKind.Namespaced && ns != "" {
						_, exists, _ := store.GetByKey(storeKey)
						if !exists {
							cacheKey := reportKey(name, ns, typ, repName)
							c.mu.Lock()
							delete(c.items, cacheKey)
							delete(c.reportKeys, cacheKey)
							c.cache.Del(c.hashKey(cacheKey))
							if keyStr, ok := c.keyMap[c.hashKey(cacheKey)]; ok && keyStr == cacheKey {
								delete(c.keyMap, c.hashKey(cacheKey))
							}
							c.mu.Unlock()
							utils.LogDebug("Removed stale cache entry", map[string]interface{}{
								"cluster":   name,
								"namespace": ns,
								"type":      typ,
								"name":      repName,
							})
						}
					} else {
						items := store.List()
						found := false
						for _, item := range items {
							if obj, ok := item.(interface{ GetName() string }); ok {
								if obj.GetName() == repName {
									found = true
									break
								}
							}
						}
						if !found {
							cacheKey := reportKey(name, ns, typ, repName)
							c.mu.Lock()
							delete(c.items, cacheKey)
							delete(c.reportKeys, cacheKey)
							c.cache.Del(c.hashKey(cacheKey))
							if keyStr, ok := c.keyMap[c.hashKey(cacheKey)]; ok && keyStr == cacheKey {
								delete(c.keyMap, c.hashKey(cacheKey))
							}
							c.mu.Unlock()
							utils.LogDebug("Removed stale cache entry", map[string]interface{}{
								"cluster":   name,
								"namespace": ns,
								"type":      typ,
								"name":      repName,
							})
						}
					}
				}
			}(clusterName, clusterClient, batch)
		}
	}
	wg.Wait()
	
	utils.LogInfo("Cache validation and cleanup completed")
}

func ValidateAndCleanupCache(ctx context.Context) {
	cache := GetCache()
	if cache != nil {
		cache.ValidateAndCleanup(ctx)
	}
}

func HasCacheData() bool {
	cache := GetCache()
	if cache != nil {
		return cache.HasCacheData()
	}
	return false
}

type CacheUpdaterImpl struct{}

func NewCacheUpdater() kubernetes.CacheUpdater {
	return &CacheUpdaterImpl{}
}

func (c *CacheUpdaterImpl) SetReport(cluster, namespace, reportType, name string, report *kubernetes.Report) {
	cache := getCache()
	if cache == nil {
		utils.LogError("Cache is nil in SetReport", map[string]interface{}{
			"cluster":   cluster,
			"namespace": namespace,
			"type":      reportType,
			"name":      name,
		})
		return
	}

	apiReport := Report{
		Type:      reportType,
		Cluster:   cluster,
		Namespace: namespace,
		Name:      name,
		Status:    report.Status,
		Data:      report.Data,
		UpdatedAt: time.Now(),
	}

	key := reportKey(cluster, namespace, reportType, name)
	cache.Set(key, apiReport, 7*24*time.Hour)
}

func (c *CacheUpdaterImpl) DeleteReport(cluster, namespace, reportType, name string) {
	cache := getCache()
	if cache == nil {
		return
	}

	key := reportKey(cluster, namespace, reportType, name)
	cache.Delete(key)

	// Also delete detail cache
	detailKey := reportDetailKey(cluster, namespace, reportType, name)
	cache.Delete(detailKey)
}

func (c *CacheUpdaterImpl) IncrementCount(cluster, namespace, reportType string, hasVuln bool) {
	IncrementReportCount(cluster, namespace, reportType, hasVuln)
}

func (c *CacheUpdaterImpl) DecrementCount(cluster, namespace, reportType string, hasVuln bool) {
	DecrementReportCount(cluster, namespace, reportType, hasVuln)
}

func (c *CacheUpdaterImpl) AdjustVulnCount(cluster, namespace, reportType string, delta int) {
	AdjustVulnCount(cluster, namespace, reportType, delta)
}

// reportDetailKey returns the cache key for full report details
func reportDetailKey(cluster, ns, typ, name string) string {
	return fmt.Sprintf("detail:%s:%s:%s:%s", cluster, ns, typ, name)
}

// GetReportDetail retrieves full report details from cache
func GetReportDetail(cluster, namespace, reportType, name string) (Report, bool) {
	cache := getCache()
	if cache == nil {
		return Report{}, false
	}

	key := reportDetailKey(cluster, namespace, reportType, name)
	if value, found := cache.Get(key); found {
		if report, ok := value.(Report); ok {
			return report, true
		}
		// Try JSON conversion
		if mapVal, ok := value.(map[string]interface{}); ok {
			b, err := json.Marshal(mapVal)
			if err == nil {
				var report Report
				if err := json.Unmarshal(b, &report); err == nil {
					return report, true
				}
			}
		}
	}
	return Report{}, false
}

// SetReportDetail stores full report details in cache
func SetReportDetail(report Report) {
	cache := getCache()
	if cache == nil {
		return
	}

	key := reportDetailKey(report.Cluster, report.Namespace, report.Type, report.Name)
	// Use random TTL between 5-10 minutes to avoid thundering herd
	ttl := 5*time.Minute + time.Duration(rand.Intn(5))*time.Minute
	cache.Set(key, report, ttl)
}

// RefreshReportDetailAsync fetches full report from K8s and updates cache asynchronously
// Uses a deduplication mechanism to prevent multiple concurrent refreshes for the same report
func RefreshReportDetailAsync(cluster, namespace, reportType, name string, reportKind config.ReportKind) {
	key := reportDetailKey(cluster, namespace, reportType, name)
	
	// Check if refresh is already in progress
	if _, inProgress := refreshInProgress.LoadOrStore(key, true); inProgress {
		// Refresh already in progress, skip
		utils.LogDebug("Async refresh already in progress, skipping", map[string]interface{}{
			"cluster":   cluster,
			"namespace": namespace,
			"type":      reportType,
			"name":      name,
		})
		return
	}
	
	go func() {
		// Ensure we clear the flag when done (must be in goroutine, not main function)
		defer refreshInProgress.Delete(key)
		
		clusterClient := GetClusterClient(cluster)
		if clusterClient == nil {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		fullReport, err := clusterClient.Client.GetReportDetails(ctx, reportKind, namespace, name)
		if err != nil {
			utils.LogDebug("Async refresh failed", map[string]interface{}{
				"cluster":   cluster,
				"namespace": namespace,
				"type":      reportType,
				"name":      name,
				"error":     err.Error(),
			})
			return
		}

		if fullReport != nil {
			report := Report{
				Type:      reportType,
				Cluster:   cluster,
				Namespace: namespace,
				Name:      name,
				Status:    fullReport.Status,
				Data:      fullReport.Data,
				UpdatedAt: time.Now(),
			}
			SetReportDetail(report)
			utils.LogDebug("Async refresh completed", map[string]interface{}{
				"cluster":   cluster,
				"namespace": namespace,
				"type":      reportType,
				"name":      name,
			})
		}
	}()
}

// countKey generates a key for the counter map
// Format: "<cluster>:<type>" for cluster-level, "<cluster>:<ns>:<type>" for namespace-level
func countKey(cluster, namespace, reportType string) string {
	if namespace == "" {
		return fmt.Sprintf("%s:%s", cluster, reportType)
	}
	return fmt.Sprintf("%s:%s:%s", cluster, namespace, reportType)
}

// IncrementReportCount increments the report count for a given cluster/namespace/type
func IncrementReportCount(cluster, namespace, reportType string, hasVuln bool) {
	counters.mu.Lock()
	defer counters.mu.Unlock()

	// Update cluster-level count
	clusterKey := countKey(cluster, "", reportType)
	if counters.counts[clusterKey] == nil {
		counters.counts[clusterKey] = &counterPair{}
	}
	counters.counts[clusterKey].total++
	if hasVuln {
		counters.counts[clusterKey].withVuln++
	}

	// Update namespace-level count (if namespace is not empty)
	if namespace != "" {
		nsKey := countKey(cluster, namespace, reportType)
		if counters.counts[nsKey] == nil {
			counters.counts[nsKey] = &counterPair{}
		}
		counters.counts[nsKey].total++
		if hasVuln {
			counters.counts[nsKey].withVuln++
		}
	}
}

// DecrementReportCount decrements the report count for a given cluster/namespace/type
func DecrementReportCount(cluster, namespace, reportType string, hasVuln bool) {
	counters.mu.Lock()
	defer counters.mu.Unlock()

	// Update cluster-level count
	clusterKey := countKey(cluster, "", reportType)
	if cp := counters.counts[clusterKey]; cp != nil {
		if cp.total > 0 {
			cp.total--
		}
		if hasVuln && cp.withVuln > 0 {
			cp.withVuln--
		}
	}

	// Update namespace-level count (if namespace is not empty)
	if namespace != "" {
		nsKey := countKey(cluster, namespace, reportType)
		if cp := counters.counts[nsKey]; cp != nil {
			if cp.total > 0 {
				cp.total--
			}
			if hasVuln && cp.withVuln > 0 {
				cp.withVuln--
			}
		}
	}
}

// AdjustVulnCount adjusts only the withVuln counter by delta (used when vuln status changes on update)
func AdjustVulnCount(cluster, namespace, reportType string, delta int) {
	counters.mu.Lock()
	defer counters.mu.Unlock()

	// Update cluster-level vuln count
	clusterKey := countKey(cluster, "", reportType)
	if cp := counters.counts[clusterKey]; cp != nil {
		cp.withVuln += delta
		if cp.withVuln < 0 {
			cp.withVuln = 0
		}
	}

	// Update namespace-level vuln count (if namespace is not empty)
	if namespace != "" {
		nsKey := countKey(cluster, namespace, reportType)
		if cp := counters.counts[nsKey]; cp != nil {
			cp.withVuln += delta
			if cp.withVuln < 0 {
				cp.withVuln = 0
			}
		}
	}
}

// GetReportCounts returns the total and withVulnerabilities count for a cluster/type
// If cluster is empty, returns counts across all clusters for the given type
func GetReportCounts(cluster, reportType string) (total, withVuln int, found bool) {
	counters.mu.RLock()
	defer counters.mu.RUnlock()

	if cluster != "" {
		// Specific cluster
		key := countKey(cluster, "", reportType)
		if cp := counters.counts[key]; cp != nil {
			return cp.total, cp.withVuln, true
		}
		return 0, 0, false
	}

	// Aggregate across all clusters
	for key, cp := range counters.counts {
		// Only count cluster-level keys (format: "cluster:type", not "cluster:ns:type")
		parts := strings.Split(key, ":")
		if len(parts) == 2 && parts[1] == reportType {
			total += cp.total
			withVuln += cp.withVuln
			found = true
		}
	}
	return total, withVuln, found
}

// GetReportCountsByNamespace returns counts filtered by namespace(s)
func GetReportCountsByNamespace(cluster, reportType string, namespaces []string) (total, withVuln int, found bool) {
	// If no namespace filter or "all" is in the list, return cluster-level counts
	hasAll := false
	for _, ns := range namespaces {
		if ns == "all" {
			hasAll = true
			break
		}
	}

	if len(namespaces) == 0 || hasAll {
		// Call GetReportCounts directly without holding the lock to avoid deadlock
		return GetReportCounts(cluster, reportType)
	}

	// Sum counts for specified namespaces
	counters.mu.RLock()
	defer counters.mu.RUnlock()

	for _, ns := range namespaces {
		key := countKey(cluster, ns, reportType)
		if cp := counters.counts[key]; cp != nil {
			total += cp.total
			withVuln += cp.withVuln
			found = true
		}
	}
	return total, withVuln, found
}

// ResetReportCounts clears all counters (used during re-initialization)
func ResetReportCounts() {
	counters.mu.Lock()
	defer counters.mu.Unlock()
	counters.counts = make(map[string]*counterPair)
}

// GetReportDetailWithTTL retrieves report detail and its remaining TTL
func GetReportDetailWithTTL(cluster, namespace, reportType, name string) (Report, bool, time.Duration) {
	cache := getCache()
	if cache == nil {
		return Report{}, false, 0
	}

	key := reportDetailKey(cluster, namespace, reportType, name)

	// Check items map for TTL info
	cache.mu.RLock()
	item, exists := cache.items[key]
	cache.mu.RUnlock()

	if !exists {
		return Report{}, false, 0
	}

	// Calculate remaining TTL
	remaining := time.Duration(item.Expiration-time.Now().Unix()) * time.Second
	if remaining <= 0 {
		return Report{}, false, 0
	}

	// Get the actual value
	if value, found := cache.Get(key); found {
		if report, ok := value.(Report); ok {
			return report, true, remaining
		}
		// Try JSON conversion
		if mapVal, ok := value.(map[string]interface{}); ok {
			b, err := json.Marshal(mapVal)
			if err == nil {
				var report Report
				if err := json.Unmarshal(b, &report); err == nil {
					return report, true, remaining
				}
			}
		}
	}
	return Report{}, false, 0
}

func init() {
	if err := LoadCache(); err != nil {
		utils.LogWarning("Failed to initialize cache", map[string]interface{}{"error": err.Error()})
		return
	}
	cache = GetCache()
	if cache == nil {
		utils.LogWarning("Cache is nil after initialization", nil)
	}
}
