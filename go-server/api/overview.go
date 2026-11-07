package api

import (
	"fmt"
	"net/http"
	"runtime/debug"
	"sort"
	"strconv"
	"sync"
	"time"
	"trivy-ui/auth"
	"trivy-ui/utils"
)

// Overview and trend endpoints, scoped to what the caller may read.

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

	key := fmt.Sprintf("%s\x00%s\x00%d\x00%d", clusterFilter, scope.Fingerprint, getTypeVersion("", ""), workloadGeneration(h.clusterReg))
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
	overview := aggregateOverview(h.reportSummaries(), func(report Report) bool {
		return (clusterFilter == "" || report.Cluster == clusterFilter) && scope.CanRead(report.Cluster, report.Namespace)
	}, registryWorkloadResolver(h.clusterReg))
	if clusterFilter == "" {
		overview.VulnerableNamespaces = []NamespaceSummary{}
	} else {
		overview.VulnerableClusters = []ClusterSummary{}
	}
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
		kind    string
	}
	aggregates := make(map[trendKey]TrendRecord)
	add := func(key trendKey, record TrendRecord) {
		aggregate := aggregates[key]
		aggregate.Timestamp = key.bucket
		aggregate.Cluster = key.cluster
		aggregate.Kind = key.kind
		aggregate.Critical += record.Critical
		aggregate.High += record.High
		aggregate.Medium += record.Medium
		aggregate.Low += record.Low
		aggregate.Unknown += record.Unknown
		aggregate.FixableCritical += record.FixableCritical
		aggregate.FixableHigh += record.FixableHigh
		aggregates[key] = aggregate
	}
	for _, record := range records {
		if record.Namespace == "" || !scope.CanRead(record.Cluster, record.Namespace) {
			continue
		}
		bucket := record.Timestamp.UTC().Truncate(time.Hour)
		add(trendKey{bucket: bucket, cluster: record.Cluster, kind: record.Kind}, record)
		if cluster == "" {
			add(trendKey{bucket: bucket, kind: record.Kind}, record)
		}
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
