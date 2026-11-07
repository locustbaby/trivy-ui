package api

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
	"trivy-ui/auth"
	"trivy-ui/config"
	"trivy-ui/utils"
)

// Trend history: one record per hour for the fleet, each cluster and each
// namespace scope, kept for 90 days in trend-history.json.

type trendSnapshot struct {
	SchemaVersion       int               `json:"schemaVersion"`
	GeneratedAt         time.Time         `json:"generatedAt"`
	ClusterFingerprints map[string]string `json:"clusterFingerprints"`
	Items               []TrendRecord     `json:"items"`
}

func (c *Cache) recordTrend() {
	records := c.trendHistory()
	now := time.Now()

	// Every known cluster and namespace gets a record, also when it has no
	// findings, so charts drop to zero instead of keeping the last value.
	scopes := make(map[string]map[string]struct{})
	for _, client := range GetAllClusterClients() {
		client.mu.RLock()
		scopes[client.Name] = map[string]struct{}{auth.ClusterScopedNamespace: {}}
		for _, namespace := range client.Namespaces {
			scopes[client.Name][namespace] = struct{}{}
		}
		client.mu.RUnlock()
	}
	for _, record := range vulnerabilityTrendRecords(c.ReportSummaries(), registryWorkloadResolver(GetDefaultRegistry()), scopes) {
		record.Timestamp = now
		records = append(records, record)
	}

	// A process restart can run recordTrend twice in the same hour. Replace the
	// existing bucket rather than appending a second point for the same scope.
	buckets := make(map[string]TrendRecord, len(records))
	for _, record := range records {
		if record.Timestamp.Before(now.Add(-90 * 24 * time.Hour)) {
			continue
		}
		record.Timestamp = record.Timestamp.UTC().Truncate(time.Hour)
		key := fmt.Sprintf("%d\x00%s\x00%s\x00%s", record.Timestamp.Unix(), record.Cluster, record.Namespace, record.Kind)
		buckets[key] = record
	}
	records = records[:0]
	for _, record := range buckets {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Timestamp.Equal(records[j].Timestamp) {
			if records[i].Cluster == records[j].Cluster {
				if records[i].Namespace == records[j].Namespace {
					return records[i].Kind < records[j].Kind
				}
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

// TrendKindVulnerabilities marks trend records that count vulnerability
// reports only. Records without a kind come from older versions, which added
// up every report type.
const TrendKindVulnerabilities = "vulnerabilities"

// vulnerabilityTrendRecords counts vulnerability reports (retired ReplicaSets
// excluded) for the whole fleet, every cluster and every namespace scope.
// scopes lists clusters and namespaces that get a record even when empty.
func vulnerabilityTrendRecords(reports []Report, resolve workloadResolverFunc, scopes map[string]map[string]struct{}) []TrendRecord {
	type scope struct{ cluster, namespace string }
	totals := map[scope]*TrendRecord{{}: {}}
	ensure := func(key scope) *TrendRecord {
		if totals[key] == nil {
			totals[key] = &TrendRecord{Cluster: key.cluster, Namespace: key.namespace}
		}
		return totals[key]
	}
	for cluster, namespaces := range scopes {
		ensure(scope{cluster: cluster})
		for namespace := range namespaces {
			ensure(scope{cluster: cluster, namespace: namespace})
		}
	}
	for _, report := range reports {
		if reportFamily(report.Type) != familyVulnerabilities || resolve(report).Retired {
			continue
		}
		namespace := report.Namespace
		if namespace == "" {
			namespace = auth.ClusterScopedNamespace
		}
		counts := countReport(report)
		for _, key := range []scope{{}, {cluster: report.Cluster}, {cluster: report.Cluster, namespace: namespace}} {
			record := ensure(key)
			record.Critical += counts.critical
			record.High += counts.high
			record.Medium += counts.medium
			record.Low += counts.low
			record.Unknown += counts.unknown
			record.FixableCritical += counts.fixableCritical
			record.FixableHigh += counts.fixableHigh
		}
	}
	records := make([]TrendRecord, 0, len(totals))
	for _, record := range totals {
		record.Kind = TrendKindVulnerabilities
		records = append(records, *record)
	}
	return records
}

type TrendRecord struct {
	Timestamp time.Time `json:"timestamp"`
	Cluster   string    `json:"cluster"`
	Namespace string    `json:"namespace,omitempty"`
	// Kind "vulnerabilities": vulnerability reports only. Empty: recorded by an
	// older version that added up every report type.
	Kind            string `json:"kind,omitempty"`
	Critical        int    `json:"critical"`
	High            int    `json:"high"`
	Medium          int    `json:"medium"`
	Low             int    `json:"low,omitempty"`
	Unknown         int    `json:"unknown,omitempty"`
	FixableCritical int    `json:"fixable_critical,omitempty"`
	FixableHigh     int    `json:"fixable_high,omitempty"`
}
