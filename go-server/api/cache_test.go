package api

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dgraph-io/ristretto"
)

func TestWritePrivateAtomicCreatesParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "cache.json")
	want := []byte(`{"ok":true}`)

	if err := writePrivateAtomic(path, want); err != nil {
		t.Fatalf("writePrivateAtomic() error = %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("file contents = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("file mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestParseByteSize(t *testing.T) {
	tests := map[string]int64{
		"256Mi": 256 << 20,
		"1Gi":   1 << 30,
		"512KB": 512 << 10,
		"1024":  1024,
	}
	for input, expected := range tests {
		got, err := parseByteSize(input)
		if err != nil || got != expected {
			t.Fatalf("parseByteSize(%q) = %d, %v; want %d", input, got, err, expected)
		}
	}
}

func TestGetReportsByRefsReportsMissingEntries(t *testing.T) {
	ristrettoCache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1000,
		MaxCost:     1 << 20,
		BufferItems: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := &Cache{
		cache:      ristrettoCache,
		items:      make(map[string]CacheItem),
		reportKeys: make(map[string]bool),
		typeIndex:  make(map[string]map[string]bool),
	}
	existing := ReportRef{Cluster: "cluster-a", Namespace: "ns-a", Type: "vulnerabilityreports", Name: "present"}
	c.Set(reportKey(existing.Cluster, existing.Namespace, existing.Type, existing.Name), Report{
		Cluster: existing.Cluster, Namespace: existing.Namespace, Type: existing.Type, Name: existing.Name,
	}, time.Hour)
	items, missing := c.GetReportsByRefs([]ReportRef{
		existing,
		{Cluster: "cluster-a", Namespace: "ns-a", Type: "vulnerabilityreports", Name: "deleted"},
	})
	if len(items) != 1 || missing != 1 {
		t.Fatalf("got %d items and %d missing entries, want 1 and 1", len(items), missing)
	}
}

func TestReportCapacityAdmissionIsSerialized(t *testing.T) {
	ristrettoCache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1000,
		MaxCost:     1 << 20,
		BufferItems: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := &Cache{
		cache:             ristrettoCache,
		summaryMaxEntries: 1,
		items:             make(map[string]CacheItem),
		reportKeys:        make(map[string]bool),
		typeIndex:         make(map[string]map[string]bool),
		capacityClusters:  make(map[string]bool),
	}

	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			key := reportKey("cluster-a", "namespace-a", "vulnerabilityreports", fmt.Sprintf("report-%d", i))
			c.Set(key, Report{Cluster: "cluster-a", Namespace: "namespace-a", Type: "vulnerabilityreports", Name: fmt.Sprintf("report-%d", i)}, time.Hour)
		}(i)
	}
	group.Wait()

	c.mu.RLock()
	count := len(c.reportKeys)
	c.mu.RUnlock()
	if count != 1 {
		t.Fatalf("report capacity admitted %d entries, want 1", count)
	}
}

func TestDetailSnapshotRoundTrip(t *testing.T) {
	detailFile := filepath.Join(t.TempDir(), "detail-cache.json")
	newCache := func() *Cache {
		ristrettoCache, err := ristretto.NewCache(&ristretto.Config{
			NumCounters: 1000,
			MaxCost:     1 << 20,
			BufferItems: 64,
		})
		if err != nil {
			t.Fatal(err)
		}
		return &Cache{
			cache:                ristrettoCache,
			detailFile:           detailFile,
			detailPersist:        true,
			detailMaxSize:        1 << 20,
			detailStaleRetention: time.Hour,
			items:                make(map[string]CacheItem),
			reportKeys:           make(map[string]bool),
			typeIndex:            make(map[string]map[string]bool),
		}
	}

	first := newCache()
	report := Report{Cluster: "cluster-a", Namespace: "tenant-a", Type: "vulnerabilityreports", Name: "report-a", ResourceVersion: "7", Data: map[string]interface{}{"report": map[string]interface{}{"summary": map[string]interface{}{"highCount": float64(1)}}}}
	first.SetClusterFingerprint("cluster-a", "fingerprint-a")
	first.Set(reportDetailKey(report.Cluster, report.Namespace, report.Type, report.Name), report, time.Hour)
	first.mu.Lock()
	item := first.items[reportDetailKey(report.Cluster, report.Namespace, report.Type, report.Name)]
	now := time.Now().UTC()
	item.FetchedAt = now
	item.FreshUntil = now.Add(time.Hour)
	item.RetainUntil = now.Add(24 * time.Hour)
	item.ClusterFingerprint = "fingerprint-a"
	first.items[reportDetailKey(report.Cluster, report.Namespace, report.Type, report.Name)] = item
	first.mu.Unlock()
	if err := first.SaveDetailToFile(); err != nil {
		t.Fatal(err)
	}

	second := newCache()
	if err := second.LoadDetailFromFile(); err != nil {
		t.Fatal(err)
	}
	value, found := second.Get(reportDetailKey(report.Cluster, report.Namespace, report.Type, report.Name))
	if !found {
		t.Fatal("expected detail restored from snapshot")
	}
	restored, ok := value.(Report)
	if !ok || restored.ResourceVersion != "7" {
		t.Fatalf("unexpected restored detail: %#v", value)
	}
}

func TestParseReportCacheKey_Valid(t *testing.T) {
	key := "report:cluster1:default:vulnerabilityreports:my-report"
	cluster, ns, rType, name, ok := parseReportCacheKey(key)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if cluster != "cluster1" || ns != "default" || rType != "vulnerabilityreports" || name != "my-report" {
		t.Fatalf("unexpected parse: cluster=%s ns=%s type=%s name=%s", cluster, ns, rType, name)
	}
}

func TestParseReportCacheKey_ClusterScoped(t *testing.T) {
	key := "report:cluster1::clustercompliancereports:cis"
	cluster, ns, _, _, ok := parseReportCacheKey(key)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if cluster != "cluster1" || ns != "" {
		t.Fatalf("unexpected cluster=%s ns=%q", cluster, ns)
	}
}

func TestParseReportCacheKey_WrongPrefix(t *testing.T) {
	_, _, _, _, ok := parseReportCacheKey("detail:c:ns:type:name")
	if ok {
		t.Fatal("expected ok=false for non-report prefix")
	}
}

func TestParseReportCacheKey_TooFewParts(t *testing.T) {
	_, _, _, _, ok := parseReportCacheKey("report:cluster:ns")
	if ok {
		t.Fatal("expected ok=false for too-few parts")
	}
}

func TestReportTypeFromKey_Valid(t *testing.T) {
	key := "report:c1:ns:vulnerabilityreports:name"
	typ := reportTypeFromKey(key)
	if typ != "vulnerabilityreports" {
		t.Fatalf("expected vulnerabilityreports got %s", typ)
	}
}

func TestReportTypeFromKey_WrongPrefix(t *testing.T) {
	typ := reportTypeFromKey("detail:c:ns:type:name")
	if typ != "" {
		t.Fatalf("expected empty got %s", typ)
	}
}

func TestExtractSummaryCounts_NestedReport(t *testing.T) {
	r := Report{
		Data: map[string]interface{}{
			"report": map[string]interface{}{
				"summary": map[string]interface{}{
					"criticalCount": float64(3),
					"highCount":     float64(7),
					"mediumCount":   float64(1),
					"lowCount":      float64(0),
				},
			},
		},
	}
	c, h, m, l := extractSummaryCounts(r)
	if c != 3 || h != 7 || m != 1 || l != 0 {
		t.Fatalf("got c=%d h=%d m=%d l=%d", c, h, m, l)
	}
}

func TestExtractSummaryCounts_FlatSummary(t *testing.T) {
	r := Report{
		Data: map[string]interface{}{
			"summary": map[string]interface{}{
				"criticalCount": float64(0),
				"highCount":     float64(2),
				"mediumCount":   float64(5),
				"lowCount":      float64(10),
			},
		},
	}
	c, h, m, l := extractSummaryCounts(r)
	if c != 0 || h != 2 || m != 5 || l != 10 {
		t.Fatalf("got c=%d h=%d m=%d l=%d", c, h, m, l)
	}
}

func TestExtractSummaryCounts_NilData(t *testing.T) {
	r := Report{}
	c, h, m, l := extractSummaryCounts(r)
	if c != 0 || h != 0 || m != 0 || l != 0 {
		t.Fatal("expected all zeros for nil data")
	}
}

func TestHasVulnerabilitiesInReport_True(t *testing.T) {
	r := Report{
		Data: map[string]interface{}{
			"report": map[string]interface{}{
				"summary": map[string]interface{}{
					"criticalCount": float64(1),
				},
			},
		},
	}
	if !hasVulnerabilitiesInReport(r) {
		t.Fatal("expected true")
	}
}

func TestHasVulnerabilitiesInReport_False(t *testing.T) {
	r := Report{
		Data: map[string]interface{}{
			"report": map[string]interface{}{
				"summary": map[string]interface{}{
					"criticalCount": float64(0),
					"highCount":     float64(0),
				},
			},
		},
	}
	if hasVulnerabilitiesInReport(r) {
		t.Fatal("expected false")
	}
}

func TestIncrementDecrementCount_Symmetry(t *testing.T) {
	ResetReportCounts()
	IncrementReportCount("c1", "ns", "vuln", true)
	IncrementReportCount("c1", "ns", "vuln", true)
	IncrementReportCount("c1", "ns", "vuln", false)

	total, withVuln, found := GetReportCounts("c1", "vuln")
	if !found || total != 3 || withVuln != 2 {
		t.Fatalf("after increments: total=%d withVuln=%d found=%v", total, withVuln, found)
	}

	DecrementReportCount("c1", "ns", "vuln", true)
	total, withVuln, _ = GetReportCounts("c1", "vuln")
	if total != 2 || withVuln != 1 {
		t.Fatalf("after decrement: total=%d withVuln=%d", total, withVuln)
	}
	ResetReportCounts()
}

func TestIncrementCount_NamespaceLevel(t *testing.T) {
	ResetReportCounts()
	IncrementReportCount("c1", "kube-system", "vuln", false)
	IncrementReportCount("c1", "default", "vuln", true)

	total, withVuln, found := GetReportCountsByNamespace("c1", "vuln", []string{"kube-system"})
	if !found || total != 1 || withVuln != 0 {
		t.Fatalf("namespace filter: total=%d withVuln=%d found=%v", total, withVuln, found)
	}
	ResetReportCounts()
}

func TestQueryCacheInvalidatesByTypeGeneration(t *testing.T) {
	query := ReportQuery{Type: "vuln", Cluster: "c", Page: 1, PageSize: 10}
	oldKey := refIndexCacheKey(query, getTypeVersion(query.Cluster, query.Type))
	queryResultCache.Store(oldKey, SortedRefIndex{Total: 99, Generation: getTypeVersion(query.Cluster, query.Type)})
	incrementTypeVersion(query.Cluster, query.Type)
	newKey := refIndexCacheKey(query, getTypeVersion(query.Cluster, query.Type))
	if _, ok := queryResultCache.Load(newKey); ok {
		t.Fatal("type generation should invalidate the previous query result")
	}
	queryResultCache.Delete(oldKey)
}

func TestReportKey_Format(t *testing.T) {
	key := reportKey("cluster1", "default", "vuln", "my-report")
	expected := "report:cluster1:default:vuln:my-report"
	if key != expected {
		t.Fatalf("expected %s got %s", expected, key)
	}
}

func TestRistrettoEvictionDoesNotRemoveAuthoritativeItems(t *testing.T) {
	ristrettoCache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 10,
		MaxCost:     1,
		BufferItems: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := &Cache{
		cache:      ristrettoCache,
		items:      make(map[string]CacheItem),
		reportKeys: make(map[string]bool),
		typeIndex:  make(map[string]map[string]bool),
	}
	key := reportKey("cluster", "namespace", "vulnerabilityreports", "name")
	c.Set(key, Report{Cluster: "cluster", Namespace: "namespace", Type: "vulnerabilityreports", Name: "name"}, time.Hour)
	if _, ok := c.Get(key); !ok {
		t.Fatal("report should remain available from the authoritative item map")
	}
}

func TestEstimateSize_Primitives(t *testing.T) {
	cases := []struct {
		v    interface{}
		minN int64
	}{
		{nil, 1},
		{"hello", 5},
		{true, 1},
		{42, 8},
		{float64(3.14), 8},
	}
	for _, tc := range cases {
		got := estimateSize(tc.v)
		if got < tc.minN {
			t.Errorf("estimateSize(%v)=%d < %d", tc.v, got, tc.minN)
		}
	}
}

func TestClusterKey(t *testing.T) {
	if clusterKey("prod") != "cluster:prod" {
		t.Fatal("wrong cluster key")
	}
}

func TestNamespaceKey(t *testing.T) {
	if namespaceKey("prod", "default") != "namespace:prod:default" {
		t.Fatalf("wrong namespace key: %s", namespaceKey("prod", "default"))
	}
}

func TestGetReports_IncludesClusterScoped(t *testing.T) {
	if err := InitCache(); err != nil {
		t.Skipf("cannot init cache: %v", err)
	}
	c := GetCache()
	c.Set(reportKey("c1", "", "clusterscoped", "r1"), Report{
		Type: "clusterscoped", Cluster: "c1", Namespace: "", Name: "r1",
	}, 0)
	c.Set(reportKey("c1", "default", "clusterscoped", "r2"), Report{
		Type: "clusterscoped", Cluster: "c1", Namespace: "default", Name: "r2",
	}, 0)

	reports := c.GetReports("clusterscoped", "", []string{"kube-system"})
	hasClusterScoped := false
	hasNamespaced := false
	for _, r := range reports {
		if r.Name == "r1" {
			hasClusterScoped = true
		}
		if r.Name == "r2" {
			hasNamespaced = true
		}
	}
	if !hasClusterScoped {
		t.Error("cluster-scoped report should always be included with namespace filter")
	}
	if hasNamespaced {
		t.Error("namespaced report in 'default' should be excluded when filter is 'kube-system'")
	}
	c.Delete(reportKey("c1", "", "clusterscoped", "r1"))
	c.Delete(reportKey("c1", "default", "clusterscoped", "r2"))
}

func TestGetReports_NamespaceFilterMatch(t *testing.T) {
	if err := InitCache(); err != nil {
		t.Skipf("cannot init cache: %v", err)
	}
	c := GetCache()
	typ := fmt.Sprintf("testtype-%d", 9999)
	c.Set(reportKey("c", "ns-a", typ, "r1"), Report{Type: typ, Cluster: "c", Namespace: "ns-a", Name: "r1"}, 0)
	c.Set(reportKey("c", "ns-b", typ, "r2"), Report{Type: typ, Cluster: "c", Namespace: "ns-b", Name: "r2"}, 0)

	reports := c.GetReports(typ, "", []string{"ns-a"})
	if len(reports) != 1 || reports[0].Name != "r1" {
		t.Fatalf("expected only r1 got %v", reports)
	}
	c.Delete(reportKey("c", "ns-a", typ, "r1"))
	c.Delete(reportKey("c", "ns-b", typ, "r2"))
}

func TestBuildSortKey_Ordering(t *testing.T) {
	k1 := BuildSortKey("c1", "a-ns", "VulnerabilityReport", "rep-1")
	k2 := BuildSortKey("c1", "b-ns", "VulnerabilityReport", "rep-2")
	kClusterScoped := BuildSortKey("c1", "", "ClusterVulnerabilityReport", "cluster-rep")
	kCluster2 := BuildSortKey("c2", "a-ns", "VulnerabilityReport", "rep-1")

	if !(k1 < k2) {
		t.Fatalf("expected k1 < k2, got k1=%q k2=%q", k1, k2)
	}
	if !(k2 < kClusterScoped) {
		t.Fatalf("expected namespaced < cluster-scoped, got k2=%q kClusterScoped=%q", k2, kClusterScoped)
	}
	if !(kClusterScoped < kCluster2) {
		t.Fatalf("expected cluster c1 < c2, got kClusterScoped=%q kCluster2=%q", kClusterScoped, kCluster2)
	}
}

func TestQueryService_SortedRefIndexPagination(t *testing.T) {
	if err := InitCache(); err != nil {
		t.Skipf("cannot init cache: %v", err)
	}
	cacheSvc := NewCacheServiceImpl()
	querySvc := NewQueryService(cacheSvc)
	typ := "test-pagination-type"

	for i := 0; i < 25; i++ {
		name := fmt.Sprintf("report-%02d", i)
		r := Report{
			Type:      typ,
			Cluster:   "cluster-1",
			Namespace: "default",
			Name:      name,
		}
		cacheSvc.Set(reportKey("cluster-1", "default", typ, name), r, time.Hour)
	}

	// Fetch Page 1 (size 10)
	q1 := ReportQuery{
		Type:     typ,
		Cluster:  "cluster-1",
		Page:     1,
		PageSize: 10,
	}
	res1 := querySvc.ListReports(q1)
	if res1.Total != 25 || len(res1.Items) != 10 {
		t.Fatalf("expected total=25, items=10 for page 1, got total=%d items=%d", res1.Total, len(res1.Items))
	}
	if res1.Items[0].Name != "report-00" || res1.Items[9].Name != "report-09" {
		t.Fatalf("unexpected page 1 items: first=%s, last=%s", res1.Items[0].Name, res1.Items[9].Name)
	}

	// Fetch Page 2 (size 10) - should reuse cached sorted index
	q2 := ReportQuery{
		Type:     typ,
		Cluster:  "cluster-1",
		Page:     2,
		PageSize: 10,
	}
	res2 := querySvc.ListReports(q2)
	if res2.Total != 25 || len(res2.Items) != 10 {
		t.Fatalf("expected total=25, items=10 for page 2, got total=%d items=%d", res2.Total, len(res2.Items))
	}
	if res2.Items[0].Name != "report-10" || res2.Items[9].Name != "report-19" {
		t.Fatalf("unexpected page 2 items: first=%s, last=%s", res2.Items[0].Name, res2.Items[9].Name)
	}

	// Fetch Page 3 (size 10)
	q3 := ReportQuery{
		Type:     typ,
		Cluster:  "cluster-1",
		Page:     3,
		PageSize: 10,
	}
	res3 := querySvc.ListReports(q3)
	if res3.Total != 25 || len(res3.Items) != 5 {
		t.Fatalf("expected total=25, items=5 for page 3, got total=%d items=%d", res3.Total, len(res3.Items))
	}
	if res3.Items[0].Name != "report-20" || res3.Items[4].Name != "report-24" {
		t.Fatalf("unexpected page 3 items: first=%s, last=%s", res3.Items[0].Name, res3.Items[4].Name)
	}

	// Clean up
	for i := 0; i < 25; i++ {
		name := fmt.Sprintf("report-%02d", i)
		cacheSvc.Delete(reportKey("cluster-1", "default", typ, name))
	}
}
