package api

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"trivy-ui/auth"
)

type ReportQuery struct {
	Type           string
	Cluster        string
	Namespaces     []string
	Search         string
	OnlyVulnerable bool
	Page           int
	PageSize       int
	Access         auth.AccessSnapshot
}

type QueryResult struct {
	Total               int
	WithVulnerabilities int
	Items               []Report
	Incomplete          bool
}

type SortedRefIndex struct {
	Total               int
	WithVulnerabilities int
	Refs                []ReportRef
	Generation          uint64
}

type QueryService interface {
	ListReports(q ReportQuery) QueryResult
}

type contextualQueryService interface {
	ListReportsContext(context.Context, ReportQuery) QueryResult
}

func listReports(ctx context.Context, service QueryService, q ReportQuery) QueryResult {
	if contextual, ok := service.(contextualQueryService); ok {
		return contextual.ListReportsContext(ctx, q)
	}
	return service.ListReports(q)
}

type queryServiceImpl struct {
	cache CacheService
}

type queryCacheEntry struct {
	value     SortedRefIndex
	expiresAt time.Time
	createdAt time.Time
	element   *list.Element
}

type queryCacheStore struct {
	mu       sync.Mutex
	entries  map[string]queryCacheEntry
	order    *list.List
	maxSize  int
	maxBytes int64
	bytes    int64
	ttl      time.Duration
}

func newQueryCacheStore() *queryCacheStore {
	return &queryCacheStore{
		entries:  make(map[string]queryCacheEntry),
		order:    list.New(),
		maxSize:  10000,
		maxBytes: 64 * 1024 * 1024,
		ttl:      30 * time.Second,
	}
}

func (c *queryCacheStore) Load(key string) (SortedRefIndex, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return SortedRefIndex{}, false
	}
	if time.Now().After(entry.expiresAt) {
		c.removeLocked(key, entry)
		return SortedRefIndex{}, false
	}
	c.order.MoveToBack(entry.element)
	return entry.value, true
}

func (c *queryCacheStore) Store(key string, value SortedRefIndex) {
	c.mu.Lock()
	defer c.mu.Unlock()
	value.Refs = append([]ReportRef(nil), value.Refs...)
	now := time.Now()
	if existing, ok := c.entries[key]; ok {
		c.removeLocked(key, existing)
	}
	newEntry := queryCacheEntry{value: value, expiresAt: now.Add(c.ttl), createdAt: now}
	newSize := queryCacheEntrySize(newEntry)
	for len(c.entries) >= c.maxSize || (c.maxBytes > 0 && c.bytes+newSize > c.maxBytes) {
		oldest := c.order.Front()
		if oldest == nil {
			break
		}
		oldestKey := oldest.Value.(string)
		c.removeLocked(oldestKey, c.entries[oldestKey])
	}
	if c.maxBytes > 0 && newSize > c.maxBytes {
		return
	}
	newEntry.element = c.order.PushBack(key)
	c.entries[key] = newEntry
	c.bytes += newSize
}

func (c *queryCacheStore) DeletePrefix(prefix string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key := range c.entries {
		if strings.HasPrefix(key, prefix) {
			c.removeLocked(key, c.entries[key])
		}
	}
}

func (c *queryCacheStore) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[key]; ok {
		c.removeLocked(key, entry)
	}
}

func (c *queryCacheStore) removeLocked(key string, entry queryCacheEntry) {
	if entry.element != nil {
		c.order.Remove(entry.element)
	}
	c.bytes -= queryCacheEntrySize(entry)
	delete(c.entries, key)
}

func queryCacheEntrySize(entry queryCacheEntry) int64 {
	// Count Ref headers as well as the string data they keep alive.
	size := int64(32) + int64(len(entry.value.Refs))*int64(unsafe.Sizeof(ReportRef{}))
	for _, ref := range entry.value.Refs {
		size += int64(len(ref.Cluster) + len(ref.Namespace) + len(ref.Type) + len(ref.Name))
	}
	return size
}

func (c *queryCacheStore) Range(fn func(key string, value SortedRefIndex) bool) {
	c.mu.Lock()
	entries := make(map[string]SortedRefIndex, len(c.entries))
	for key, entry := range c.entries {
		entries[key] = entry.value
	}
	c.mu.Unlock()
	for key, value := range entries {
		if !fn(key, value) {
			return
		}
	}
}

func (c *queryCacheStore) Configure(maxEntries int, maxBytes int64, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if maxEntries > 0 {
		c.maxSize = maxEntries
	}
	if maxBytes > 0 {
		c.maxBytes = maxBytes
	}
	if ttl > 0 {
		c.ttl = ttl
	}
	for len(c.entries) > c.maxSize || (c.maxBytes > 0 && c.bytes > c.maxBytes) {
		oldest := c.order.Front()
		if oldest == nil {
			break
		}
		key := oldest.Value.(string)
		c.removeLocked(key, c.entries[key])
	}
}

var queryResultCache = newQueryCacheStore()

type queryFlight struct {
	done  chan struct{}
	index SortedRefIndex
}

var queryFlights sync.Map

func NewQueryService(cache CacheService) QueryService {
	return &queryServiceImpl{cache: cache}
}

func (s *queryServiceImpl) ListReports(q ReportQuery) QueryResult {
	return s.ListReportsContext(context.Background(), q)
}

func (s *queryServiceImpl) ListReportsContext(ctx context.Context, q ReportQuery) QueryResult {
	if ctx.Err() != nil {
		return QueryResult{}
	}
	if cache, ok := s.cache.(*CacheServiceImpl); ok && cache.CapacityExceededFor(q.Cluster) {
		return QueryResult{Incomplete: true, Items: []Report{}}
	}
	if q.Page < 1 {
		q.Page = 1
	}
	if q.PageSize <= 0 {
		q.PageSize = 50
	}

	for attempt := 0; attempt < 2; attempt++ {
		generation := getTypeVersion(q.Cluster, q.Type)
		cacheKey := refIndexCacheKey(q, generation)
		index := s.resolveIndex(ctx, q, cacheKey, generation)
		if ctx.Err() != nil {
			return QueryResult{}
		}
		if index.Generation != generation || getTypeVersion(q.Cluster, q.Type) != generation {
			queryResultCache.Delete(cacheKey)
			continue
		}

		pageRefs := paginateRefs(index.Refs, q.Page, q.PageSize)
		items, missing := s.cache.GetReportsByRefs(pageRefs)
		if missing > 0 || !itemsCanRead(items, q.Access) || getTypeVersion(q.Cluster, q.Type) != generation {
			queryResultCache.Delete(cacheKey)
			continue
		}

		return QueryResult{
			Total:               index.Total,
			WithVulnerabilities: index.WithVulnerabilities,
			Items:               items,
		}
	}

	return QueryResult{Incomplete: true, Items: []Report{}}
}

func (s *queryServiceImpl) resolveIndex(ctx context.Context, q ReportQuery, cacheKey string, generation uint64) SortedRefIndex {
	if cached, ok := queryResultCache.Load(cacheKey); ok {
		return cached
	}

	flight := &queryFlight{done: make(chan struct{})}
	actual, loaded := queryFlights.LoadOrStore(cacheKey, flight)
	if loaded {
		select {
		case <-actual.(*queryFlight).done:
		case <-ctx.Done():
			return SortedRefIndex{}
		}
		return actual.(*queryFlight).index
	}
	defer func() {
		close(flight.done)
		queryFlights.Delete(cacheKey)
	}()

	if cached, ok := queryResultCache.Load(cacheKey); ok {
		flight.index = cached
		return cached
	}

	index := s.buildIndex(q, generation)
	flight.index = index
	if index.Generation == getTypeVersion(q.Cluster, q.Type) {
		queryResultCache.Store(cacheKey, index)
	}
	return index
}

func (s *queryServiceImpl) buildIndex(q ReportQuery, generation uint64) SortedRefIndex {
	rawReports := s.cache.GetRawReportsByType(q.Type, q.Cluster, q.Namespaces)
	filteredReports := make([]Report, 0, len(rawReports))
	searchLower := strings.ToLower(q.Search)
	withVuln := 0
	for _, report := range rawReports {
		report = ensureReportRef(report)
		if q.Access.Fingerprint != "" && !q.Access.CanRead(report.Cluster, report.Namespace) {
			continue
		}
		hasVuln := hasVulnerabilitiesInReport(report)
		if q.OnlyVulnerable && !hasVuln {
			continue
		}
		if q.Search != "" && !reportMatchesSearch(report, searchLower) {
			continue
		}
		filteredReports = append(filteredReports, report)
		if hasVuln {
			withVuln++
		}
	}

	sort.Slice(filteredReports, func(i, j int) bool {
		return filteredReports[i].SortKey < filteredReports[j].SortKey
	})
	refs := make([]ReportRef, len(filteredReports))
	for i, report := range filteredReports {
		refs[i] = report.Ref
	}
	return SortedRefIndex{
		Total:               len(refs),
		WithVulnerabilities: withVuln,
		Refs:                refs,
		Generation:          generation,
	}
}

func refIndexCacheKey(q ReportQuery, generation uint64) string {
	payload := struct {
		Type           string   `json:"type"`
		Cluster        string   `json:"cluster"`
		Namespaces     []string `json:"namespaces"`
		Search         string   `json:"search"`
		OnlyVulnerable bool     `json:"onlyVulnerable"`
		Access         string   `json:"access"`
		Generation     uint64   `json:"generation"`
	}{
		Type:           q.Type,
		Cluster:        q.Cluster,
		Namespaces:     normalizeQueryValues(q.Namespaces),
		Search:         strings.ToLower(q.Search),
		OnlyVulnerable: q.OnlyVulnerable,
		Access:         q.Access.Fingerprint,
		Generation:     generation,
	}
	data, _ := json.Marshal(payload)
	digest := sha256.Sum256(data)
	return "refs:" + hex.EncodeToString(digest[:])
}

func normalizeQueryValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	normalized := append([]string(nil), values...)
	sort.Strings(normalized)
	result := normalized[:0]
	for _, value := range normalized {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func itemsCanRead(items []Report, access auth.AccessSnapshot) bool {
	if access.Fingerprint == "" {
		return true
	}
	for _, item := range items {
		if !access.CanRead(item.Cluster, item.Namespace) {
			return false
		}
	}
	return true
}

func paginateRefs(refs []ReportRef, page, pageSize int) []ReportRef {
	total := len(refs)
	if total == 0 || page < 1 || pageSize <= 0 {
		return []ReportRef{}
	}
	start := (page - 1) * pageSize
	if start >= total {
		return []ReportRef{}
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	return append([]ReportRef(nil), refs[start:end]...)
}

func reportMatchesSearch(report Report, searchLower string) bool {
	if strings.Contains(strings.ToLower(report.Name), searchLower) ||
		strings.Contains(strings.ToLower(report.Cluster), searchLower) ||
		strings.Contains(strings.ToLower(report.Namespace), searchLower) {
		return true
	}

	dataMap, ok := report.Data.(map[string]interface{})
	if !ok {
		return false
	}

	var artifact interface{}
	if reportData, found := dataMap["report"]; found {
		if reportDataMap, ok := reportData.(map[string]interface{}); ok {
			artifact = reportDataMap["artifact"]
		}
	}
	if artifact == nil {
		artifact = dataMap["artifact"]
	}
	artifactMap, ok := artifact.(map[string]interface{})
	if !ok {
		return false
	}
	repository, ok := artifactMap["repository"].(string)
	if !ok {
		return false
	}
	return strings.Contains(strings.ToLower(repository), searchLower)
}
