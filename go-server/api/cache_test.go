package api

import (
	"fmt"
	"testing"
)

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

func TestEvictQueryCacheForType(t *testing.T) {
	queryResultCache.Store("vuln|c||foo|false|1|10|0", QueryResult{Total: 99})
	queryResultCache.Store("config|c||bar|false|1|10|0", QueryResult{Total: 55})

	evictQueryCacheForType("vuln")

	if _, ok := queryResultCache.Load("vuln|c||foo|false|1|10|0"); ok {
		t.Fatal("vuln entry should have been evicted")
	}
	if _, ok := queryResultCache.Load("config|c||bar|false|1|10|0"); !ok {
		t.Fatal("config entry should NOT have been evicted")
	}
	queryResultCache.Delete("config|c||bar|false|1|10|0")
}

func TestReportKey_Format(t *testing.T) {
	key := reportKey("cluster1", "default", "vuln", "my-report")
	expected := "report:cluster1:default:vuln:my-report"
	if key != expected {
		t.Fatalf("expected %s got %s", expected, key)
	}
}

func TestHashKey_Deterministic(t *testing.T) {
	c := &Cache{}
	h1 := c.hashKey("report:c:ns:type:name")
	h2 := c.hashKey("report:c:ns:type:name")
	if h1 != h2 {
		t.Fatal("hash not deterministic")
	}
}

func TestHashKey_Distinct(t *testing.T) {
	c := &Cache{}
	keys := []string{"a", "b", "report:c1:ns:vuln:r1", "report:c2:ns:vuln:r1"}
	seen := make(map[uint64]string)
	for _, k := range keys {
		h := c.hashKey(k)
		if prev, ok := seen[h]; ok {
			t.Fatalf("collision: %q and %q hash to %d", k, prev, h)
		}
		seen[h] = k
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
