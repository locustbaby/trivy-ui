package api

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"trivy-ui/kubernetes"
	"trivy-ui/utils"
)

var globalCache *Cache
var cache *Cache

// CacheItem 缓存项，不再有过期时间
type CacheItem struct {
	Value     interface{} `json:"value"`
	UpdatedAt int64       `json:"updated_at"` // 最后更新时间（用于监控，不用于淘汰）
}

// Cache 作为权威数据源的缓存
// 数据只能通过 Informer 的 Delete 事件删除，不会因为 TTL 或 LRU 被淘汰
type Cache struct {
	mu         sync.RWMutex
	items      map[string]CacheItem // 所有缓存项
	reportKeys map[string]bool      // 快速查找 report 键
	cacheFile  string               // 持久化文件路径
	
	// 统计信息
	stats struct {
		sync.RWMutex
		TotalSets    int64
		TotalDeletes int64
		TotalGets    int64
		LastSaveTime time.Time
	}
}

func InitCache() error {
	globalCache = &Cache{
		items:      make(map[string]CacheItem),
		reportKeys: make(map[string]bool),
		cacheFile:  "cache.json",
	}
	
	globalCache.stats.LastSaveTime = time.Now()

	// 从文件加载缓存
	if err := globalCache.LoadFromFile(); err != nil {
		utils.LogWarning("Failed to load cache from file", map[string]interface{}{"error": err.Error()})
	}

	// 启动定期持久化
	go globalCache.periodicSave()
	
	// 启动定期统计
	go globalCache.periodicStats()

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

// Get 获取缓存项
func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	c.stats.Lock()
	c.stats.TotalGets++
	c.stats.Unlock()
	
	item, found := c.items[key]
	if !found {
		return nil, false
	}
	return item.Value, true
}

// Set 设置缓存项（忽略 expiration 参数，保持接口兼容性）
func (c *Cache) Set(key string, value interface{}, expiration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	isReport := strings.HasPrefix(key, "report:")
	
	c.items[key] = CacheItem{
		Value:     value,
		UpdatedAt: time.Now().Unix(),
	}
	
	if isReport {
		c.reportKeys[key] = true
	}
	
	c.stats.Lock()
	c.stats.TotalSets++
	c.stats.Unlock()
}

// Delete 删除缓存项（只应由 Informer 调用）
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	delete(c.items, key)
	if strings.HasPrefix(key, "report:") {
		delete(c.reportKeys, key)
	}
	
	c.stats.Lock()
	c.stats.TotalDeletes++
	c.stats.Unlock()
	
	utils.LogDebug("Cache item deleted", map[string]interface{}{
		"key": key,
	})
}

// Items 返回所有缓存项的副本
func (c *Cache) Items() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	result := make(map[string]interface{}, len(c.items))
	for k, item := range c.items {
		result[k] = item.Value
	}
	
	return result
}

// GetReportKeys 返回所有 report 键
func (c *Cache) GetReportKeys() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	keys := make([]string, 0, len(c.reportKeys))
	for k := range c.reportKeys {
		keys = append(keys, k)
	}
	return keys
}

// GetStats 获取缓存统计信息
func (c *Cache) GetStats() map[string]interface{} {
	c.mu.RLock()
	itemCount := len(c.items)
	reportCount := len(c.reportKeys)
	c.mu.RUnlock()
	
	c.stats.RLock()
	defer c.stats.RUnlock()
	
	return map[string]interface{}{
		"total_items":    itemCount,
		"report_items":   reportCount,
		"total_sets":     c.stats.TotalSets,
		"total_deletes":  c.stats.TotalDeletes,
		"total_gets":     c.stats.TotalGets,
		"last_save_time": c.stats.LastSaveTime.Format(time.RFC3339),
	}
}

// LoadFromFile 从文件加载缓存
func (c *Cache) LoadFromFile() error {
	if _, err := os.Stat(c.cacheFile); os.IsNotExist(err) {
		utils.LogInfo("Cache file does not exist, starting with empty cache", map[string]interface{}{
			"file": c.cacheFile,
		})
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

	loadedCount := 0
	for k, item := range items {
		c.items[k] = item
		if strings.HasPrefix(k, "report:") {
			c.reportKeys[k] = true
		}
		loadedCount++
	}

	utils.LogInfo("Cache loaded from file", map[string]interface{}{
		"file":  c.cacheFile,
		"count": loadedCount,
	})

	return nil
}

// SaveToFile 保存缓存到文件
func (c *Cache) SaveToFile() error {
	c.mu.RLock()
	itemsCopy := make(map[string]CacheItem, len(c.items))
	for k, v := range c.items {
		itemsCopy[k] = v
	}
	c.mu.RUnlock()

	tmpFile := c.cacheFile + ".tmp"
	
	f, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(itemsCopy); err != nil {
		f.Close()
		os.Remove(tmpFile)
		return fmt.Errorf("failed to encode cache data: %w", err)
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpFile)
		return fmt.Errorf("failed to sync file: %w", err)
	}

	f.Close()

	if _, err := os.Stat(c.cacheFile); err == nil {
		if err := os.Remove(c.cacheFile); err != nil {
			os.Remove(tmpFile)
			return fmt.Errorf("failed to remove old cache file: %w", err)
		}
	}

	if err := os.Rename(tmpFile, c.cacheFile); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	c.stats.Lock()
	c.stats.LastSaveTime = time.Now()
	c.stats.Unlock()

	utils.LogDebug("Cache saved to file", map[string]interface{}{
		"file":  c.cacheFile,
		"count": len(itemsCopy),
	})

	return nil
}

// periodicSave 定期保存缓存到文件
func (c *Cache) periodicSave() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// 异步保存，避免阻塞
		go func() {
			// 设置保存超时
			done := make(chan error, 1)
			go func() {
				done <- c.SaveToFile()
			}()

			select {
			case err := <-done:
				if err != nil {
					utils.LogWarning("Failed to save cache", map[string]interface{}{"error": err.Error()})
				}
			case <-time.After(30 * time.Second):
				utils.LogWarning("Cache save timeout", map[string]interface{}{"timeout": "30s"})
			}
		}()
	}
}

// periodicStats 定期输出统计信息
func (c *Cache) periodicStats() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		stats := c.GetStats()
		utils.LogInfo("Cache statistics", stats)
	}
}

// Helper functions for cache keys
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

// CacheUpdaterImpl 实现 Informer 的缓存更新接口
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
	cache.Set(key, apiReport, 0) // expiration 参数被忽略
	
	utils.LogDebug("Report updated in cache", map[string]interface{}{
		"cluster":   cluster,
		"namespace": namespace,
		"type":      reportType,
		"name":      name,
	})
}

func (c *CacheUpdaterImpl) DeleteReport(cluster, namespace, reportType, name string) {
	cache := getCache()
	if cache == nil {
		return
	}

	key := reportKey(cluster, namespace, reportType, name)
	cache.Delete(key)
	
	utils.LogInfo("Report deleted from cache", map[string]interface{}{
		"cluster":   cluster,
		"namespace": namespace,
		"type":      reportType,
		"name":      name,
	})
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
