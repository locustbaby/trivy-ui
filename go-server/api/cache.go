package api

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"trivy-ui/auth"
	"trivy-ui/config"
	"trivy-ui/kubernetes"
	"trivy-ui/utils"

	"github.com/dgraph-io/ristretto"
)

var globalCache *Cache
var cacheInitMu sync.Mutex

// Track ongoing async refreshes to prevent duplicate refreshes
var refreshInProgress sync.Map // map[string]bool, key is reportDetailKey

var typeVersions sync.Map // map[cluster + "\x00" + type]string to *atomic.Uint64
var repositoryVersion atomic.Uint64

func incrementTypeVersion(cluster, reportType string) {
	key := cluster + "\x00" + reportType
	version := &atomic.Uint64{}
	actual, _ := typeVersions.LoadOrStore(key, version)
	actual.(*atomic.Uint64).Add(1)
	repositoryVersion.Add(1)
}

func getTypeVersion(cluster, reportType string) uint64 {
	if cluster == "" {
		return repositoryVersion.Load()
	}
	key := cluster + "\x00" + reportType
	if val, ok := typeVersions.Load(key); ok {
		return val.(*atomic.Uint64).Load()
	}
	return 0
}

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
	Value              interface{} `json:"value"`
	Expiration         int64       `json:"expiration"`
	FetchedAt          time.Time   `json:"fetchedAt,omitempty"`
	FreshUntil         time.Time   `json:"freshUntil,omitempty"`
	RetainUntil        time.Time   `json:"retainUntil,omitempty"`
	Stale              bool        `json:"stale,omitempty"`
	ClusterFingerprint string      `json:"clusterFingerprint,omitempty"`
}

type summarySnapshot struct {
	Version             int                  `json:"schemaVersion"`
	GeneratedAt         time.Time            `json:"generatedAt"`
	ClusterFingerprints map[string]string    `json:"clusterFingerprints"`
	Items               map[string]CacheItem `json:"items"`
}

type Cache struct {
	cache                *ristretto.Cache
	mu                   sync.RWMutex
	reportWriteMu        sync.Mutex
	cacheFile            string
	detailFile           string
	detailPersist        bool
	detailMaxSize        int64
	detailTTL            time.Duration
	detailStaleRetention time.Duration
	summaryMaxEntries    int
	snapshotMaxSize      int64
	capacityExceeded     bool
	capacityClusters     map[string]bool
	items                map[string]CacheItem
	reportKeys           map[string]bool
	typeIndex            map[string]map[string]bool
	clusterFingerprints  map[string]string
	trendMu              sync.RWMutex
	trendRecords         []TrendRecord
	trendLoaded          bool
}

func InitCache() error {
	cacheInitMu.Lock()
	defer cacheInitMu.Unlock()
	if globalCache != nil {
		return nil
	}
	cfg := config.Get()
	cacheFilePath := "cache.json"
	detailFilePath := "detail-cache.json"
	if cfg.DataPath != "" && cfg.DataPath != "." {
		cacheFilePath = filepath.Join(cfg.DataPath, "cache.json")
		detailFilePath = filepath.Join(cfg.DataPath, "detail-cache.json")
	}
	detailMaxSize := int64(256 * 1024 * 1024)
	summaryMaxEntries := 100000
	if raw := strings.TrimSpace(os.Getenv("CACHE_SUMMARY_MAX_ENTRIES")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value <= 0 {
			return fmt.Errorf("invalid CACHE_SUMMARY_MAX_ENTRIES %q", raw)
		}
		summaryMaxEntries = value
	}
	snapshotMaxSize := int64(512 * 1024 * 1024)
	if raw := strings.TrimSpace(os.Getenv("CACHE_SNAPSHOT_MAX_SIZE")); raw != "" {
		value, err := parseByteSize(raw)
		if err != nil || value <= 0 {
			return fmt.Errorf("invalid CACHE_SNAPSHOT_MAX_SIZE %q", raw)
		}
		snapshotMaxSize = value
	}
	detailPersist := true
	if raw := strings.TrimSpace(os.Getenv("CACHE_DETAIL_PERSIST")); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("invalid CACHE_DETAIL_PERSIST %q", raw)
		}
		detailPersist = value
	}
	if raw := strings.TrimSpace(os.Getenv("CACHE_DETAIL_MAX_SIZE")); raw != "" {
		if value, err := parseByteSize(raw); err == nil && value > 0 {
			detailMaxSize = value
		} else {
			return fmt.Errorf("invalid CACHE_DETAIL_MAX_SIZE %q", raw)
		}
	}
	detailTTL := 10 * time.Minute
	if raw := strings.TrimSpace(os.Getenv("CACHE_DETAIL_TTL")); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil || value <= 0 {
			return fmt.Errorf("invalid CACHE_DETAIL_TTL %q", raw)
		}
		detailTTL = value
	}
	detailStaleRetention := 24 * time.Hour
	if raw := strings.TrimSpace(os.Getenv("CACHE_DETAIL_STALE_RETENTION")); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil || value <= 0 {
			return fmt.Errorf("invalid CACHE_DETAIL_STALE_RETENTION %q", raw)
		}
		detailStaleRetention = value
	}
	queryMaxEntries := 10000
	if raw := strings.TrimSpace(os.Getenv("CACHE_QUERY_MAX_ENTRIES")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value <= 0 {
			return fmt.Errorf("invalid CACHE_QUERY_MAX_ENTRIES %q", raw)
		}
		queryMaxEntries = value
	}
	queryMaxBytes := int64(64 * 1024 * 1024)
	if raw := strings.TrimSpace(os.Getenv("CACHE_QUERY_MAX_SIZE")); raw != "" {
		value, err := parseByteSize(raw)
		if err != nil || value <= 0 {
			return fmt.Errorf("invalid CACHE_QUERY_MAX_SIZE %q", raw)
		}
		queryMaxBytes = value
	}
	queryTTL := 30 * time.Second
	if raw := strings.TrimSpace(os.Getenv("CACHE_QUERY_TTL")); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil || value <= 0 {
			return fmt.Errorf("invalid CACHE_QUERY_TTL %q", raw)
		}
		queryTTL = value
	}

	globalCache = &Cache{
		cacheFile:            cacheFilePath,
		detailFile:           detailFilePath,
		detailPersist:        detailPersist,
		detailMaxSize:        detailMaxSize,
		detailTTL:            detailTTL,
		detailStaleRetention: detailStaleRetention,
		summaryMaxEntries:    summaryMaxEntries,
		snapshotMaxSize:      snapshotMaxSize,
		items:                make(map[string]CacheItem),
		reportKeys:           make(map[string]bool),
		typeIndex:            make(map[string]map[string]bool),
		capacityClusters:     make(map[string]bool),
		clusterFingerprints:  make(map[string]string),
	}
	queryResultCache.Configure(queryMaxEntries, queryMaxBytes, queryTTL)

	config := &ristretto.Config{
		NumCounters: 1e7,
		MaxCost:     1 << 30,
		BufferItems: 64,
	}
	ristrettoCache, err := ristretto.NewCache(config)
	if err != nil {
		return fmt.Errorf("failed to create cache: %w", err)
	}

	globalCache.cache = ristrettoCache

	if err := globalCache.LoadFromFile(); err != nil {
		utils.LogWarning("Failed to load cache from file", map[string]interface{}{"error": err.Error()})
	}
	if globalCache.detailPersist {
		if err := globalCache.LoadDetailFromFile(); err != nil {
			utils.LogWarning("Failed to load detail cache from file", map[string]interface{}{"error": err.Error()})
		}
	}

	go globalCache.periodicSave()
	go globalCache.periodicTrendRecord()

	return nil
}

func GetCache() *Cache {
	cacheInitMu.Lock()
	cache := globalCache
	cacheInitMu.Unlock()
	if cache == nil {
		if err := InitCache(); err != nil {
			utils.LogError("Failed to initialize cache", map[string]interface{}{"error": err.Error()})
			return nil
		}
		cacheInitMu.Lock()
		cache = globalCache
		cacheInitMu.Unlock()
	}
	return cache
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
		if item.Expiration > now {
			return item.Value, true
		}
	}
	return nil, false
}

func (c *Cache) Set(key string, value interface{}, expiration time.Duration) {
	cost := int64(len(key)) + estimateSize(value)
	isReport := strings.HasPrefix(key, "report:")
	if isReport {
		// Report admission is serialized separately from the cache state lock.
		// This prevents two new reports from both passing the capacity check.
		c.reportWriteMu.Lock()
		defer c.reportWriteMu.Unlock()
		c.mu.Lock()
		_, exists := c.items[key]
		atCapacity := c.summaryMaxEntries > 0 && len(c.reportKeys) >= c.summaryMaxEntries
		if atCapacity && !exists {
			if c.capacityClusters == nil {
				c.capacityClusters = make(map[string]bool)
			}
			c.capacityExceeded = true
			if cluster, _, _, _, ok := parseReportCacheKey(key); ok {
				c.capacityClusters[cluster] = true
			}
			c.mu.Unlock()
			utils.LogWarning("Report summary capacity exceeded; new report was rejected", map[string]interface{}{"key": key, "maxEntries": c.summaryMaxEntries})
			return
		}
		c.mu.Unlock()
	}
	if expiration <= 0 {
		if isReport {
			expiration = 7 * 24 * time.Hour
		} else {
			expiration = 10 * time.Second
		}
	}
	c.cache.SetWithTTL(key, value, cost, expiration)
	c.mu.Lock()
	c.items[key] = CacheItem{
		Value:      value,
		Expiration: time.Now().Add(expiration).Unix(),
	}
	if isReport {
		c.reportKeys[key] = true
		if cluster, _, typ, _, ok := parseReportCacheKey(key); ok && typ != "" {
			if c.typeIndex[typ] == nil {
				c.typeIndex[typ] = make(map[string]bool)
			}
			c.typeIndex[typ][key] = true
			incrementTypeVersion(cluster, typ)
		}
	}
	var detailEvictions []string
	if strings.HasPrefix(key, "detail:") {
		detailEvictions = c.enforceDetailLimitLocked()
	}
	c.mu.Unlock()
	for _, evictedKey := range detailEvictions {
		c.cache.Del(evictedKey)
	}
}

func (c *Cache) Delete(key string) {
	isReport := strings.HasPrefix(key, "report:")
	if isReport {
		c.reportWriteMu.Lock()
		defer c.reportWriteMu.Unlock()
	}
	c.cache.Del(key)
	c.mu.Lock()
	var removedReport Report
	var removed bool
	if isReport {
		if item, found := c.items[key]; found {
			removedReport, removed = decodeReportValue(item.Value)
		}
	}
	delete(c.items, key)
	if strings.HasPrefix(key, "report:") {
		delete(c.reportKeys, key)
		if cluster, _, typ, _, ok := parseReportCacheKey(key); ok && typ != "" {
			if idx, ok := c.typeIndex[typ]; ok {
				delete(idx, key)
			}
			incrementTypeVersion(cluster, typ)
		}
	}
	c.mu.Unlock()
	if removed {
		DecrementReportCount(removedReport.Cluster, removedReport.Namespace, removedReport.Type, hasVulnerabilitiesInReport(removedReport))
	}
}

func (c *Cache) DeleteReportEntry(cluster, namespace, reportType, name string) {
	c.deleteReportEntryByKey(reportKey(cluster, namespace, reportType, name))
}

func (c *Cache) deleteReportEntryByKey(key string) {
	cluster, namespace, reportType, name, ok := parseReportCacheKey(key)
	if !ok {
		c.Delete(key)
		return
	}

	_, found := c.Get(key)
	if !found {
		c.Delete(key)
		c.Delete(reportDetailKey(cluster, namespace, reportType, name))
		return
	}

	c.Delete(key)
	c.Delete(reportDetailKey(cluster, namespace, reportType, name))
}

func (c *Cache) Items() map[string]interface{} {
	return c.itemsByPrefix("")
}

func (c *Cache) ItemsByPrefix(prefix string) map[string]interface{} {
	return c.itemsByPrefix(prefix)
}

func (c *Cache) itemsByPrefix(prefix string) map[string]interface{} {
	c.mu.RLock()
	capacity := len(c.items)
	if prefix != "" {
		capacity = 0
	}
	itemsCopy := make(map[string]CacheItem, capacity)
	reportKeysCopy := make(map[string]bool, len(c.reportKeys))
	for k, v := range c.items {
		if prefix != "" && !strings.HasPrefix(k, prefix) {
			continue
		}
		itemsCopy[k] = v
	}
	for k := range c.reportKeys {
		if prefix != "" && !strings.HasPrefix(k, prefix) {
			continue
		}
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

		if found && item.Expiration > now {
			result[k] = value
		}
	}

	// Also check reportKeys that might be in ristretto but not in items yet.
	for k := range reportKeysCopy {
		if _, exists := result[k]; !exists {
			c.mu.RLock()
			item, tracked := c.items[k]
			c.mu.RUnlock()
			if tracked && item.Expiration > now {
				val, found := c.cache.Get(k)
				if !found {
					val = item.Value
				}
				result[k] = val
			}
		}
	}

	return result
}

func (c *Cache) ReportSummaries() []Report {
	now := time.Now().Unix()
	c.mu.RLock()
	defer c.mu.RUnlock()

	reports := make([]Report, 0, len(c.reportKeys))
	for key := range c.reportKeys {
		item, ok := c.items[key]
		if !ok || item.Expiration <= now {
			continue
		}
		if report, ok := item.Value.(Report); ok {
			report = ensureReportRef(report)
			reports = append(reports, report)
			continue
		}
		if report, ok := convertCacheValue[Report](item.Value); ok {
			report = ensureReportRef(report)
			reports = append(reports, report)
		}
	}
	return reports
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

func (c *Cache) GetRawReportsByType(typeName, clusterFilter string, namespaceFilters []string) []Report {
	c.mu.RLock()
	idx, ok := c.typeIndex[typeName]
	if !ok {
		c.mu.RUnlock()
		return nil
	}

	var reports []Report
	for k := range idx {
		parts := strings.SplitN(k, ":", 5)
		if len(parts) < 5 {
			continue
		}
		cluster := parts[1]
		namespace := parts[2]

		if clusterFilter != "" && cluster != clusterFilter {
			continue
		}

		if len(namespaceFilters) > 0 && namespace != "" {
			matched := false
			for _, nf := range namespaceFilters {
				if nf == "all" || namespace == nf {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		if item, found := c.items[k]; found {
			if rep, ok := item.Value.(Report); ok {
				reports = append(reports, ensureReportRef(rep))
			} else if rep, ok := convertCacheValue[Report](item.Value); ok {
				reports = append(reports, ensureReportRef(rep))
			}
		}
	}
	c.mu.RUnlock()
	return reports
}

func (c *Cache) GetReportsByRefs(refs []ReportRef) ([]Report, int) {
	if len(refs) == 0 {
		return []Report{}, 0
	}
	reports := make([]Report, 0, len(refs))
	missing := 0
	now := time.Now().Unix()
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, ref := range refs {
		key := reportKey(ref.Cluster, ref.Namespace, ref.Type, ref.Name)
		if item, found := c.items[key]; found && item.Expiration > now {
			if rep, ok := item.Value.(Report); ok {
				reports = append(reports, ensureReportRef(rep))
				continue
			}
			if rep, ok := convertCacheValue[Report](item.Value); ok {
				reports = append(reports, ensureReportRef(rep))
				continue
			}
		}
		missing++
	}
	return reports, missing
}

func (c *Cache) GetReports(typeName, clusterFilter string, namespaceFilters []string) []Report {
	reports := c.GetRawReportsByType(typeName, clusterFilter, namespaceFilters)
	if len(reports) == 0 {
		return reports
	}

	sort.Slice(reports, func(i, j int) bool {
		return reports[i].SortKey < reports[j].SortKey
	})

	return reports
}

func (c *Cache) GetReportCount(reportType, cluster string) (total int, withVulnerabilities int) {
	for _, report := range c.ReportSummaries() {
		if reportType != "" && report.Type != reportType {
			continue
		}
		if cluster != "" && report.Cluster != cluster {
			continue
		}

		total++
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
	if err := os.Chmod(c.cacheFile, 0600); err != nil {
		return fmt.Errorf("failed to secure cache file: %w", err)
	}

	data, err := os.ReadFile(c.cacheFile)
	if err != nil {
		return fmt.Errorf("failed to read cache file: %w", err)
	}

	var snapshot summarySnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return fmt.Errorf("failed to unmarshal cache data: %w", err)
	}
	items := snapshot.Items
	if snapshot.Version == 0 || items == nil {
		if err := json.Unmarshal(data, &items); err != nil {
			return fmt.Errorf("failed to unmarshal legacy cache data: %w", err)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Reset counters before rebuilding from cache
	ResetReportCounts()
	if snapshot.Version > 0 && snapshot.ClusterFingerprints != nil {
		c.clusterFingerprints = snapshot.ClusterFingerprints
	}

	now := time.Now().Unix()
	for k, item := range items {
		if strings.HasPrefix(k, "detail:") || strings.HasPrefix(k, "sorted_list:") {
			continue
		}
		isReport := strings.HasPrefix(k, "report:")
		if isReport {
			if item.Expiration <= now && now-item.Expiration > int64((24*time.Hour).Seconds()) {
				continue
			}
			var report Report
			if b, err := json.Marshal(item.Value); err == nil {
				if err := json.Unmarshal(b, &report); err == nil {
					item.Value = report
				}
			}
		}
		if item.Expiration > now || isReport {
			expiration := time.Duration(item.Expiration-now) * time.Second
			if isReport {
				// A Summary restored after a restart is useful for availability,
				// but it is not fresh until an informer observes the source.
				item.Stale = true
				expiration = 24 * time.Hour
				if report, ok := item.Value.(Report); ok {
					report.Stale = true
					item.Value = report
				}
			}
			cost := int64(len(k)) + estimateSize(item.Value)
			c.cache.SetWithTTL(k, item.Value, cost, expiration)
			if isReport {
				c.items[k] = CacheItem{
					Value:              item.Value,
					Expiration:         time.Now().Add(expiration).Unix(),
					Stale:              item.Stale,
					ClusterFingerprint: item.ClusterFingerprint,
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
		}
	}
	if c.summaryMaxEntries > 0 && len(c.reportKeys) > c.summaryMaxEntries {
		c.capacityExceeded = true
		for key := range c.reportKeys {
			if cluster, _, _, _, ok := parseReportCacheKey(key); ok {
				c.capacityClusters[cluster] = true
			}
		}
	}
	return nil
}

type detailSnapshot struct {
	SchemaVersion       int                  `json:"schemaVersion"`
	Version             int                  `json:"version,omitempty"`
	GeneratedAt         time.Time            `json:"generatedAt"`
	ClusterFingerprints map[string]string    `json:"clusterFingerprints"`
	Items               map[string]CacheItem `json:"items"`
}

type trendSnapshot struct {
	SchemaVersion       int               `json:"schemaVersion"`
	GeneratedAt         time.Time         `json:"generatedAt"`
	ClusterFingerprints map[string]string `json:"clusterFingerprints"`
	Items               []TrendRecord     `json:"items"`
}

func (c *Cache) LoadDetailFromFile() error {
	if _, err := os.Stat(c.detailFile); os.IsNotExist(err) {
		return nil
	}
	if err := os.Chmod(c.detailFile, 0600); err != nil {
		return fmt.Errorf("failed to secure detail cache file: %w", err)
	}
	data, err := os.ReadFile(c.detailFile)
	if err != nil {
		return fmt.Errorf("failed to read detail cache file: %w", err)
	}

	var snapshot detailSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return fmt.Errorf("failed to unmarshal detail cache data: %w", err)
	}
	version := snapshot.SchemaVersion
	if version == 0 {
		version = snapshot.Version
	}
	if version != 1 && version != 2 {
		return fmt.Errorf("unsupported detail cache version %d", version)
	}

	now := time.Now().Unix()
	var evicted []string
	c.mu.Lock()
	if snapshot.ClusterFingerprints != nil {
		c.clusterFingerprints = snapshot.ClusterFingerprints
	}
	for key, item := range snapshot.Items {
		if !strings.HasPrefix(key, "detail:") {
			continue
		}
		if version == 1 || len(snapshot.ClusterFingerprints) == 0 || item.ClusterFingerprint == "" {
			continue
		}
		keyParts := strings.SplitN(strings.TrimPrefix(key, "detail:"), ":", 2)
		if len(keyParts) != 2 || snapshot.ClusterFingerprints[keyParts[0]] != item.ClusterFingerprint {
			continue
		}
		freshUntil := item.FreshUntil.Unix()
		if item.FreshUntil.IsZero() {
			freshUntil = item.Expiration
		}
		retainUntil := item.RetainUntil.Unix()
		if item.RetainUntil.IsZero() {
			retainUntil = item.Expiration + int64(c.detailStaleRetention.Seconds())
		}
		if freshUntil <= now {
			if retainUntil <= now {
				continue
			}
			item.Stale = true
			item.Expiration = retainUntil
		}
		if item.Expiration <= now {
			continue
		}
		if report, ok := decodeReportValue(item.Value); ok {
			report.Stale = item.Stale
			item.Value = report
		} else {
			continue
		}
		c.items[key] = item
		remaining := time.Until(time.Unix(item.Expiration, 0))
		if remaining > 0 {
			c.cache.SetWithTTL(key, item.Value, int64(len(key))+estimateSize(item.Value), remaining)
		}
	}
	evicted = c.enforceDetailLimitLocked()
	c.mu.Unlock()

	for _, key := range evicted {
		c.cache.Del(key)
	}
	return nil
}

func decodeReportValue(value interface{}) (Report, bool) {
	if report, ok := value.(Report); ok {
		return report, true
	}
	b, err := json.Marshal(value)
	if err != nil {
		return Report{}, false
	}
	var report Report
	if err := json.Unmarshal(b, &report); err != nil {
		return Report{}, false
	}
	return report, true
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
	now := time.Now().Unix()
	validItems := make(map[string]CacheItem)
	c.mu.RLock()
	for k, item := range c.items {
		if item.Expiration > now && !strings.HasPrefix(k, "detail:") && !strings.HasPrefix(k, "sorted_list:") {
			validItems[k] = item
		}
	}
	c.mu.RUnlock()

	c.mu.RLock()
	fingerprints := make(map[string]string, len(c.clusterFingerprints))
	for cluster, fingerprint := range c.clusterFingerprints {
		fingerprints[cluster] = fingerprint
	}
	c.mu.RUnlock()
	snapshot := summarySnapshot{Version: 2, GeneratedAt: time.Now().UTC(), ClusterFingerprints: fingerprints, Items: validItems}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cache data: %w", err)
	}
	if c.snapshotMaxSize > 0 && int64(len(data)) > c.snapshotMaxSize {
		return fmt.Errorf("summary cache snapshot exceeds configured limit")
	}

	if err := writePrivateAtomic(c.cacheFile, data); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}
	return nil
}

func (c *Cache) CapacityExceeded() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.capacityExceeded
}

func (c *Cache) CapacityExceededFor(cluster string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if cluster != "" {
		return c.capacityClusters[cluster]
	}
	return c.capacityExceeded
}

func (c *Cache) MarkClusterReconciled(cluster string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.capacityClusters == nil {
		return
	}
	if c.summaryMaxEntries <= 0 || len(c.reportKeys) < c.summaryMaxEntries {
		delete(c.capacityClusters, cluster)
	}
	c.capacityExceeded = len(c.capacityClusters) > 0
}

func (c *Cache) SetClusterFingerprint(cluster, fingerprint string) {
	if cluster == "" || fingerprint == "" {
		return
	}
	c.mu.RLock()
	previous := c.clusterFingerprints[cluster]
	c.mu.RUnlock()
	if previous != "" && previous != fingerprint {
		c.ClearCluster(cluster)
	}
	c.mu.Lock()
	if c.clusterFingerprints == nil {
		c.clusterFingerprints = make(map[string]string)
	}
	c.clusterFingerprints[cluster] = fingerprint
	c.mu.Unlock()
}

func SetClusterFingerprint(cluster, fingerprint string) {
	if cache := GetCache(); cache != nil {
		cache.SetClusterFingerprint(cluster, fingerprint)
	}
}

func PruneClusterCache(active []string) {
	cache := GetCache()
	if cache == nil {
		return
	}
	allowed := make(map[string]struct{}, len(active))
	for _, cluster := range active {
		allowed[cluster] = struct{}{}
	}
	cache.mu.RLock()
	clusters := make(map[string]struct{}, len(cache.clusterFingerprints))
	for cluster := range cache.clusterFingerprints {
		clusters[cluster] = struct{}{}
	}
	for key := range cache.reportKeys {
		if cluster, _, _, _, ok := parseReportCacheKey(key); ok {
			clusters[cluster] = struct{}{}
		}
	}
	cache.mu.RUnlock()
	for cluster := range clusters {
		if _, ok := allowed[cluster]; !ok {
			cache.ClearCluster(cluster)
		}
	}
}

func (c *Cache) ClearCluster(cluster string) {
	if cluster == "" {
		return
	}
	c.mu.RLock()
	keys := make([]string, 0)
	for key := range c.items {
		if c.keyBelongsToCluster(key, cluster) {
			keys = append(keys, key)
		}
	}
	c.mu.RUnlock()
	for _, key := range keys {
		c.Delete(key)
	}
	c.mu.Lock()
	delete(c.clusterFingerprints, cluster)
	delete(c.capacityClusters, cluster)
	c.capacityExceeded = len(c.capacityClusters) > 0
	c.mu.Unlock()
	repositoryVersion.Add(1)
}

func (c *Cache) keyBelongsToCluster(key, cluster string) bool {
	for _, prefix := range []string{"report:", "detail:", "namespace:", "cluster:"} {
		if strings.HasPrefix(key, prefix) {
			parts := strings.SplitN(strings.TrimPrefix(key, prefix), ":", 2)
			return len(parts) > 0 && parts[0] == cluster
		}
	}
	return false
}

func (c *Cache) SaveDetailToFile() error {
	if !c.detailPersist {
		return nil
	}
	now := time.Now().Unix()
	c.mu.RLock()
	items := make(map[string]CacheItem)
	keys := make([]string, 0)
	for key, item := range c.items {
		if strings.HasPrefix(key, "detail:") && item.Expiration > now {
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		return c.items[keys[i]].Expiration > c.items[keys[j]].Expiration
	})
	var size int64
	for _, key := range keys {
		item := c.items[key]
		itemSize := int64(len(key)) + estimateSize(item.Value)
		if c.detailMaxSize > 0 && size+itemSize > c.detailMaxSize {
			continue
		}
		items[key] = item
		size += itemSize
	}
	c.mu.RUnlock()

	c.mu.RLock()
	fingerprints := make(map[string]string, len(c.clusterFingerprints))
	for cluster, fingerprint := range c.clusterFingerprints {
		fingerprints[cluster] = fingerprint
	}
	c.mu.RUnlock()
	snapshot := detailSnapshot{SchemaVersion: 2, GeneratedAt: time.Now().UTC(), ClusterFingerprints: fingerprints, Items: items}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal detail cache data: %w", err)
	}
	if c.detailMaxSize > 0 && int64(len(data)) > c.detailMaxSize {
		return fmt.Errorf("detail cache snapshot exceeds configured limit")
	}
	if err := writePrivateAtomic(c.detailFile, data); err != nil {
		return fmt.Errorf("failed to write detail cache file: %w", err)
	}
	return nil
}

func (c *Cache) enforceDetailLimitLocked() []string {
	if c.detailMaxSize <= 0 {
		return nil
	}
	var total int64
	keys := make([]string, 0)
	for key, item := range c.items {
		if !strings.HasPrefix(key, "detail:") {
			continue
		}
		total += int64(len(key)) + estimateSize(item.Value)
		keys = append(keys, key)
	}
	if total <= c.detailMaxSize {
		return nil
	}
	sort.Slice(keys, func(i, j int) bool {
		return c.items[keys[i]].Expiration < c.items[keys[j]].Expiration
	})
	var evicted []string
	for _, key := range keys {
		if total <= c.detailMaxSize {
			break
		}
		item := c.items[key]
		total -= int64(len(key)) + estimateSize(item.Value)
		delete(c.items, key)
		evicted = append(evicted, key)
	}
	return evicted
}

func parseByteSize(raw string) (int64, error) {
	value := strings.TrimSpace(strings.ToLower(raw))
	units := []struct {
		suffix string
		factor int64
	}{
		{"gib", 1 << 30}, {"gi", 1 << 30}, {"gb", 1 << 30},
		{"mib", 1 << 20}, {"mi", 1 << 20}, {"mb", 1 << 20},
		{"kib", 1 << 10}, {"ki", 1 << 10}, {"kb", 1 << 10},
		{"b", 1},
	}
	for _, unit := range units {
		if strings.HasSuffix(value, unit.suffix) {
			number := strings.TrimSpace(strings.TrimSuffix(value, unit.suffix))
			parsed, err := strconv.ParseInt(number, 10, 64)
			if err != nil {
				return 0, err
			}
			return parsed * unit.factor, nil
		}
	}
	return strconv.ParseInt(value, 10, 64)
}

func writePrivateAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".trivy-ui-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(0600); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	return nil
}

func getCache() *Cache {
	return GetCache()
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

func BuildSortKey(cluster, namespace, typeName, name string) string {
	nsPart := namespace
	if nsPart == "" {
		nsPart = "~\x00cluster_scoped"
	} else {
		nsPart = "0\x00" + nsPart
	}
	return cluster + "\x00" + nsPart + "\x00" + typeName + "\x00" + name
}

func ensureReportRef(report Report) Report {
	if report.Ref.Cluster == "" && report.Ref.Namespace == "" && report.Ref.Type == "" && report.Ref.Name == "" {
		report.Ref = ReportRef{Cluster: report.Cluster, Namespace: report.Namespace, Type: report.Type, Name: report.Name}
	}
	if report.SortKey == "" {
		report.SortKey = BuildSortKey(report.Cluster, report.Namespace, report.Type, report.Name)
	}
	return report
}

func parseReportCacheKey(key string) (cluster, namespace, reportType, name string, ok bool) {
	if !strings.HasPrefix(key, "report:") {
		return "", "", "", "", false
	}
	parts := strings.SplitN(strings.TrimPrefix(key, "report:"), ":", 4)
	if len(parts) < 4 {
		return "", "", "", "", false
	}
	return parts[0], parts[1], parts[2], parts[3], true
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
		c.pruneExpired()
		if err := c.SaveToFile(); err != nil {
			utils.LogWarning("Failed to save cache", map[string]interface{}{"error": err.Error()})
		}
		if err := c.SaveDetailToFile(); err != nil {
			utils.LogWarning("Failed to save detail cache", map[string]interface{}{"error": err.Error()})
		}
	}
}

func (c *Cache) pruneExpired() {
	now := time.Now().Unix()
	var expired []string
	var removedReports []Report
	c.mu.Lock()
	for key, item := range c.items {
		if item.Expiration > now {
			continue
		}
		expired = append(expired, key)
		if strings.HasPrefix(key, "report:") {
			if report, ok := decodeReportValue(item.Value); ok {
				removedReports = append(removedReports, report)
			}
		}
		delete(c.items, key)
		if strings.HasPrefix(key, "report:") {
			delete(c.reportKeys, key)
			if typ := reportTypeFromKey(key); typ != "" {
				if index, ok := c.typeIndex[typ]; ok {
					delete(index, key)
				}
			}
		}
	}
	c.mu.Unlock()

	for _, key := range expired {
		c.cache.Del(key)
		if strings.HasPrefix(key, "report:") {
			if cluster, _, typ, _, ok := parseReportCacheKey(key); ok && typ != "" {
				incrementTypeVersion(cluster, typ)
			}
		}
	}
	for _, report := range removedReports {
		DecrementReportCount(report.Cluster, report.Namespace, report.Type, hasVulnerabilitiesInReport(report))
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
		utils.LogDebug("No cache data to validate")
		return
	}

	clients := GetAllClusterClients()
	if len(clients) == 0 {
		utils.LogDebug("No cluster clients available, skipping cache validation")
		return
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
		registry := config.GetGlobalRegistry()
		if clusterClient.Registry != nil {
			registry = clusterClient.Registry
		}
		reports := registry.GetAllReports()
		if len(reports) == 0 {
			utils.LogDebug("No report types discovered for cluster, skipping cache validation", map[string]interface{}{"cluster": clusterName})
			continue
		}
		reportTypesByName := make(map[string]*config.ReportKind)
		for i := range reports {
			reportTypesByName[reports[i].Name] = &reports[i]
		}
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
							c.deleteReportEntryByKey(cacheKey)
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
							c.deleteReportEntryByKey(cacheKey)
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

type CacheUpdaterImpl struct {
	reg *ClusterRegistry
}

func NewCacheUpdater(reg *ClusterRegistry) kubernetes.CacheUpdater {
	return &CacheUpdaterImpl{reg: reg}
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
		Type:            reportType,
		Cluster:         cluster,
		Namespace:       namespace,
		Name:            name,
		ResourceVersion: report.ResourceVersion,
		Status:          report.Status,
		Data:            report.Data,
		UpdatedAt:       time.Now(),
	}
	apiReport.Ref = ReportRef{Cluster: cluster, Namespace: namespace, Type: reportType, Name: name}

	key := reportKey(cluster, namespace, reportType, name)
	previous, found := cache.Get(key)
	if found {
		if previousReport, ok := decodeReportValue(previous); ok {
			if previousReport.ResourceVersion == apiReport.ResourceVersion && !previousReport.Stale {
				return
			}
			if hasVulnerabilitiesInReport(previousReport) != hasVulnerabilitiesInReport(apiReport) {
				delta := 1
				if !hasVulnerabilitiesInReport(apiReport) {
					delta = -1
				}
				AdjustVulnCount(cluster, namespace, reportType, delta)
			}
		} else {
			IncrementReportCount(cluster, namespace, reportType, hasVulnerabilitiesInReport(apiReport))
		}
		if previousReport, ok := decodeReportValue(previous); ok &&
			(previousReport.ResourceVersion != apiReport.ResourceVersion || previousReport.Stale) {
			cache.Delete(reportDetailKey(cluster, namespace, reportType, name))
		}
	} else {
		IncrementReportCount(cluster, namespace, reportType, hasVulnerabilitiesInReport(apiReport))
	}
	// Informer resync refreshes this lease while the source is healthy. If the
	// source remains unavailable, stale summaries are eventually removed.
	cache.Set(key, apiReport, 24*time.Hour)
}

func (c *CacheUpdaterImpl) InvalidateReportDetail(cluster, namespace, reportType, name string) {
	cache := getCache()
	if cache == nil {
		return
	}
	cache.Delete(reportDetailKey(cluster, namespace, reportType, name))
}

func (c *CacheUpdaterImpl) DeleteReport(cluster, namespace, reportType, name string) {
	cache := getCache()
	if cache == nil {
		return
	}

	cache.DeleteReportEntry(cluster, namespace, reportType, name)
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

func (c *CacheUpdaterImpl) UpdateSyncState(clusterName string, state string) {
	if c.reg != nil {
		if client := c.reg.Get(clusterName); client != nil {
			client.mu.Lock()
			client.SyncState = state
			client.ObservedAt = time.Now().UTC()
			client.mu.Unlock()
		}
	}
}

func (c *CacheUpdaterImpl) MarkClusterReconciled(clusterName string) {
	if cache := getCache(); cache != nil {
		cache.MarkClusterReconciled(clusterName)
	}
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
			return ensureReportRef(report), true
		}
		// Try JSON conversion
		if mapVal, ok := value.(map[string]interface{}); ok {
			b, err := json.Marshal(mapVal)
			if err == nil {
				var report Report
				if err := json.Unmarshal(b, &report); err == nil {
					return ensureReportRef(report), true
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
	ttl := cache.detailTTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if ttl >= 5*time.Minute {
		ttl += time.Duration(rand.Int63n(int64(ttl / 5)))
	}
	cache.Set(key, report, ttl)
	cache.mu.Lock()
	if item, ok := cache.items[key]; ok {
		now := time.Now().UTC()
		item.FetchedAt = now
		item.FreshUntil = now.Add(ttl)
		item.RetainUntil = now.Add(cache.detailStaleRetention)
		item.ClusterFingerprint = cache.clusterFingerprints[report.Cluster]
		cache.items[key] = item
	}
	cache.mu.Unlock()
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
				Type:            reportType,
				Cluster:         cluster,
				Namespace:       namespace,
				Name:            name,
				ResourceVersion: fullReport.ResourceVersion,
				Status:          fullReport.Status,
				Data:            fullReport.Data,
				UpdatedAt:       time.Now(),
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
	clusterFingerprint := cache.clusterFingerprints[cluster]
	cache.mu.RUnlock()

	if !exists {
		return Report{}, false, 0
	}
	if clusterFingerprint != "" && item.ClusterFingerprint != clusterFingerprint {
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
			report.Stale = item.Stale
			return ensureReportRef(report), true, remaining
		}
		// Try JSON conversion
		if mapVal, ok := value.(map[string]interface{}); ok {
			b, err := json.Marshal(mapVal)
			if err == nil {
				var report Report
				if err := json.Unmarshal(b, &report); err == nil {
					report.Stale = item.Stale
					return ensureReportRef(report), true, remaining
				}
			}
		}
	}
	return Report{}, false, 0
}

func extractSummaryCounts(report Report) (int, int, int, int) {
	if report.Data == nil {
		return 0, 0, 0, 0
	}

	data, ok := report.Data.(map[string]interface{})
	if !ok {
		return 0, 0, 0, 0
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
		return 0, 0, 0, 0
	}

	getInt := func(key string) int {
		if count, ok := summary[key].(float64); ok {
			return int(count)
		}
		if count, ok := summary[key].(int); ok {
			return count
		}
		if count, ok := summary[key].(int64); ok {
			return int(count)
		}
		return 0
	}

	return getInt("criticalCount"), getInt("highCount"), getInt("mediumCount"), getInt("lowCount")
}

func (c *Cache) GetOverviewData(clusterFilter string) *ClusterOverview {
	overview := &ClusterOverview{
		SeverityTotals:         SeverityTotals{},
		ScanTypesBreakdown:     make(map[string]TypeBreakdown),
		TopVulnerableWorkloads: make([]WorkloadSummary, 0),
		VulnerableClusters:     make([]ClusterSummary, 0),
		VulnerableNamespaces:   make([]NamespaceSummary, 0),
	}

	workloadScores := make(map[string]*WorkloadSummary)
	nsScores := make(map[string]*NamespaceSummary)
	clusterScores := make(map[string]*ClusterSummary)

	for _, report := range c.ReportSummaries() {
		if clusterFilter != "" && report.Cluster != clusterFilter {
			continue
		}

		overview.TotalReports++

		cCount, hCount, mCount, lCount := extractSummaryCounts(report)

		overview.SeverityTotals.Critical += cCount
		overview.SeverityTotals.High += hCount
		overview.SeverityTotals.Medium += mCount
		overview.SeverityTotals.Low += lCount

		tb := overview.ScanTypesBreakdown[report.Type]
		tb.Scanned++
		if cCount > 0 || hCount > 0 || mCount > 0 || lCount > 0 {
			tb.Failed++
		}
		tb.Critical += cCount
		overview.ScanTypesBreakdown[report.Type] = tb

		if cCount > 0 || hCount > 0 {
			wKey := fmt.Sprintf("%s:%s:%s:%s", report.Cluster, report.Namespace, report.Type, report.Name)
			if _, exists := workloadScores[wKey]; !exists {
				workloadScores[wKey] = &WorkloadSummary{
					Cluster: report.Cluster, Namespace: report.Namespace, Name: report.Name, Type: report.Type,
				}
			}
			workloadScores[wKey].Critical += cCount
			workloadScores[wKey].High += hCount

			nsKey := fmt.Sprintf("%s:%s", report.Cluster, report.Namespace)
			if _, exists := nsScores[nsKey]; !exists {
				nsScores[nsKey] = &NamespaceSummary{Cluster: report.Cluster, Name: report.Namespace}
			}
			nsScores[nsKey].Critical += cCount
			nsScores[nsKey].High += hCount

			cKey := report.Cluster
			if _, exists := clusterScores[cKey]; !exists {
				clusterScores[cKey] = &ClusterSummary{Name: report.Cluster}
			}
			clusterScores[cKey].Critical += cCount
			clusterScores[cKey].High += hCount
		}
	}

	for _, w := range workloadScores {
		overview.TopVulnerableWorkloads = append(overview.TopVulnerableWorkloads, *w)
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
		for _, cScore := range clusterScores {
			overview.VulnerableClusters = append(overview.VulnerableClusters, *cScore)
		}
		sort.Slice(overview.VulnerableClusters, func(i, j int) bool {
			if overview.VulnerableClusters[i].Critical != overview.VulnerableClusters[j].Critical {
				return overview.VulnerableClusters[i].Critical > overview.VulnerableClusters[j].Critical
			}
			return overview.VulnerableClusters[i].High > overview.VulnerableClusters[j].High
		})
	} else {
		for _, ns := range nsScores {
			overview.VulnerableNamespaces = append(overview.VulnerableNamespaces, *ns)
		}
		sort.Slice(overview.VulnerableNamespaces, func(i, j int) bool {
			if overview.VulnerableNamespaces[i].Critical != overview.VulnerableNamespaces[j].Critical {
				return overview.VulnerableNamespaces[i].Critical > overview.VulnerableNamespaces[j].Critical
			}
			return overview.VulnerableNamespaces[i].High > overview.VulnerableNamespaces[j].High
		})
	}

	return overview
}

func (c *Cache) recordTrend() {
	records := c.trendHistory()

	global := c.GetOverviewData("")
	now := time.Now()

	records = append(records, TrendRecord{
		Timestamp: now,
		Cluster:   "",
		Critical:  global.SeverityTotals.Critical,
		High:      global.SeverityTotals.High,
		Medium:    global.SeverityTotals.Medium,
	})

	clusterNames := make(map[string]struct{})
	for _, client := range GetAllClusterClients() {
		clusterNames[client.Name] = struct{}{}
	}
	for _, report := range c.ReportSummaries() {
		clusterNames[report.Cluster] = struct{}{}
	}
	for clusterName := range clusterNames {
		co := c.GetOverviewData(clusterName)
		records = append(records, TrendRecord{
			Timestamp: now,
			Cluster:   clusterName,
			Critical:  co.SeverityTotals.Critical,
			High:      co.SeverityTotals.High,
			Medium:    co.SeverityTotals.Medium,
		})
	}

	type trendCounts struct{ critical, high, medium int }
	scoped := make(map[string]*trendCounts)
	scopeNames := make(map[string]map[string]struct{})
	for _, client := range GetAllClusterClients() {
		client.mu.RLock()
		for _, namespace := range client.Namespaces {
			if scopeNames[client.Name] == nil {
				scopeNames[client.Name] = make(map[string]struct{})
			}
			scopeNames[client.Name][namespace] = struct{}{}
		}
		if scopeNames[client.Name] == nil {
			scopeNames[client.Name] = make(map[string]struct{})
		}
		scopeNames[client.Name][auth.ClusterScopedNamespace] = struct{}{}
		client.mu.RUnlock()
	}
	for _, report := range c.ReportSummaries() {
		scopeName := report.Namespace
		if scopeName == "" {
			scopeName = auth.ClusterScopedNamespace
		}
		if scopeNames[report.Cluster] == nil {
			scopeNames[report.Cluster] = make(map[string]struct{})
		}
		scopeNames[report.Cluster][scopeName] = struct{}{}
		counts := scoped[report.Cluster+"\x00"+scopeName]
		if counts == nil {
			counts = &trendCounts{}
			scoped[report.Cluster+"\x00"+scopeName] = counts
		}
		counts.critical, counts.high, counts.medium, _ = addSummaryCounts(counts.critical, counts.high, counts.medium, report)
	}
	for clusterName, scopes := range scopeNames {
		for scopeName := range scopes {
			key := clusterName + "\x00" + scopeName
			counts := scoped[key]
			if counts == nil {
				counts = &trendCounts{}
			}
			records = append(records, TrendRecord{
				Timestamp: now,
				Cluster:   clusterName,
				Namespace: scopeName,
				Critical:  counts.critical,
				High:      counts.high,
				Medium:    counts.medium,
			})
		}
	}

	// A process restart can run recordTrend twice in the same hour. Replace the
	// existing bucket rather than appending a second point for the same scope.
	bucket := now.UTC().Truncate(time.Hour)
	buckets := make(map[string]TrendRecord, len(records))
	for _, record := range records {
		if record.Timestamp.Before(now.Add(-90 * 24 * time.Hour)) {
			continue
		}
		record.Timestamp = record.Timestamp.UTC().Truncate(time.Hour)
		key := fmt.Sprintf("%d\x00%s\x00%s", record.Timestamp.Unix(), record.Cluster, record.Namespace)
		buckets[key] = record
	}
	globalRecord := TrendRecord{
		Timestamp: bucket,
		Cluster:   "",
		Critical:  global.SeverityTotals.Critical,
		High:      global.SeverityTotals.High,
		Medium:    global.SeverityTotals.Medium,
	}
	globalKey := fmt.Sprintf("%d\x00%s\x00%s", bucket.Unix(), globalRecord.Cluster, globalRecord.Namespace)
	buckets[globalKey] = globalRecord
	records = records[:0]
	for _, record := range buckets {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Timestamp.Equal(records[j].Timestamp) {
			if records[i].Cluster == records[j].Cluster {
				return records[i].Namespace < records[j].Namespace
			}
			return records[i].Cluster < records[j].Cluster
		}
		return records[i].Timestamp.Before(records[j].Timestamp)
	})
	c.trendMu.Lock()
	c.trendRecords = append([]TrendRecord(nil), records...)
	c.trendLoaded = true
	c.trendMu.Unlock()

	c.mu.RLock()
	fingerprints := make(map[string]string, len(c.clusterFingerprints))
	for cluster, fingerprint := range c.clusterFingerprints {
		fingerprints[cluster] = fingerprint
	}
	c.mu.RUnlock()
	b, _ := json.MarshalIndent(trendSnapshot{
		SchemaVersion:       2,
		GeneratedAt:         time.Now().UTC(),
		ClusterFingerprints: fingerprints,
		Items:               records,
	}, "", "  ")
	if err := writePrivateAtomic(trendHistoryPath(), b); err != nil {
		utils.LogWarning("Failed to save trend history", map[string]interface{}{"error": err.Error()})
	}
}

func addSummaryCounts(critical, high, medium int, report Report) (int, int, int, int) {
	c, h, m, l := extractSummaryCounts(report)
	return critical + c, high + h, medium + m, l
}

func (c *Cache) periodicTrendRecord() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	c.recordTrend()
	for range ticker.C {
		c.recordTrend()
	}
}

func (c *Cache) GetTrends(clusterFilter string, days int) []TrendRecord {
	if days <= 0 {
		days = 30
	}
	if days > 90 {
		days = 90
	}
	records := c.trendHistory()

	cutoff := time.Now().Add(-time.Duration(days*24) * time.Hour)

	var filtered []TrendRecord
	for _, r := range records {
		clusterMatches := r.Cluster == clusterFilter
		if clusterFilter == "" {
			clusterMatches = true
		}
		if clusterMatches && r.Timestamp.After(cutoff) {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func trendHistoryPath() string {
	cfg := config.Get()
	if cfg.DataPath != "" && cfg.DataPath != "." {
		return filepath.Join(cfg.DataPath, "trend-history.json")
	}
	return filepath.Join(".", "trend-history.json")
}

func (c *Cache) trendHistory() []TrendRecord {
	c.trendMu.RLock()
	if c.trendLoaded {
		records := append([]TrendRecord(nil), c.trendRecords...)
		c.trendMu.RUnlock()
		return records
	}
	c.trendMu.RUnlock()

	var records []TrendRecord
	data, err := os.ReadFile(trendHistoryPath())
	if err == nil {
		var snapshot trendSnapshot
		if json.Unmarshal(data, &snapshot) == nil && snapshot.SchemaVersion > 0 {
			records = snapshot.Items
		} else {
			_ = json.Unmarshal(data, &records)
		}
	}

	c.trendMu.Lock()
	if !c.trendLoaded {
		c.trendRecords = append([]TrendRecord(nil), records...)
		c.trendLoaded = true
	}
	result := append([]TrendRecord(nil), c.trendRecords...)
	c.trendMu.Unlock()
	return result
}
