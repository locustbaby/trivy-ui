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

	"github.com/dgraph-io/ristretto"
)

var globalCache *Cache
var cache *Cache

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
}

func InitCache() error {
	globalCache = &Cache{
		cacheFile:  "cache.json",
		items:      make(map[string]CacheItem),
		reportKeys: make(map[string]bool),
		keyMap:     make(map[uint64]string),
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
					}
					delete(globalCache.keyMap, item.Key)
				}
				globalCache.mu.Unlock()
			}
		},
	}
	cache, err := ristretto.NewCache(config)
	if err != nil {
		return fmt.Errorf("failed to create cache: %w", err)
	}

	globalCache.cache = cache

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
	value, found := c.cache.Get(key)
	if !found {
		return nil, false
	}
	return value, true
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
	if isReport {
		c.items[key] = CacheItem{
			Value:      value,
			Expiration: time.Now().Add(expiration).Unix(),
		}
		c.reportKeys[key] = true
	} else {
		c.items[key] = CacheItem{
			Value:      value,
			Expiration: time.Now().Add(expiration).Unix(),
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
	}
	c.mu.Unlock()
}

func (c *Cache) Items() map[string]interface{} {
	c.mu.RLock()
	now := time.Now().Unix()
	itemsCopy := make(map[string]CacheItem, len(c.items))
	reportKeysCopy := make(map[string]bool, len(c.reportKeys))
	for k, v := range c.items {
		itemsCopy[k] = v
	}
	for k := range c.reportKeys {
		reportKeysCopy[k] = true
	}
	c.mu.RUnlock()

	result := make(map[string]interface{}, len(itemsCopy)+len(reportKeysCopy))

	for k, item := range itemsCopy {
		if !strings.HasPrefix(k, "report:") {
			if item.Expiration > now {
				result[k] = item.Value
			}
		}
	}

	var expiredReports []string
	for k := range reportKeysCopy {
		if item, ok := itemsCopy[k]; ok {
			if item.Expiration > now {
				result[k] = item.Value
			} else {
				if val, found := c.cache.Get(k); found {
					result[k] = val
					expiredReports = append(expiredReports, k)
				}
			}
		} else {
			if val, found := c.cache.Get(k); found {
				result[k] = val
				expiredReports = append(expiredReports, k)
			}
		}
	}

	if len(expiredReports) > 0 {
		c.mu.Lock()
		for _, k := range expiredReports {
			if val, found := c.cache.Get(k); found {
				c.items[k] = CacheItem{
					Value:      val,
					Expiration: time.Now().Add(7 * 24 * time.Hour).Unix(),
				}
			}
		}
		c.mu.Unlock()
	}

	return result
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
			}
		}
	}

	return nil
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
