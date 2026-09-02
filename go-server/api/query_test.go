package api

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"trivy-ui/auth"
)

type stubCacheService struct {
	reports map[string][]Report
	trends  []TrendRecord
}

func (s *stubCacheService) Get(key string) (interface{}, bool)                 { return nil, false }
func (s *stubCacheService) Items() map[string]interface{}                      { return nil }
func (s *stubCacheService) ItemsByType(t string) map[string]interface{}        { return nil }
func (s *stubCacheService) Set(key string, value interface{}, _ time.Duration) {}
func (s *stubCacheService) Delete(key string)                                  {}
func (s *stubCacheService) DeleteReportEntry(_, _, _, _ string)                {}
func (s *stubCacheService) GetReportCount(_, _ string) (int, int)              { return 0, 0 }
func (s *stubCacheService) GetOverviewData(_ string) *ClusterOverview          { return nil }
func (s *stubCacheService) GetTrends(_ string, _ int) []TrendRecord {
	return append([]TrendRecord(nil), s.trends...)
}
func (s *stubCacheService) GetStats() map[string]interface{} { return nil }
func (s *stubCacheService) GetReports(typeName, clusterFilter string, namespaceFilters []string) []Report {
	return s.GetRawReportsByType(typeName, clusterFilter, namespaceFilters)
}
func (s *stubCacheService) GetRawReportsByType(typeName, clusterFilter string, namespaceFilters []string) []Report {
	// Mirror the real cache behaviour: cluster and namespace filters are
	// applied when reports are fetched from the cache, before buildIndex runs.
	filtered := make([]Report, 0)
	for _, report := range s.reports[typeName] {
		if clusterFilter != "" && report.Cluster != clusterFilter {
			continue
		}
		if len(namespaceFilters) > 0 {
			match := false
			for _, ns := range namespaceFilters {
				if report.Namespace == ns {
					match = true
					break
				}
			}
			// Cluster-scoped reports bypass namespace filters.
			if !match && report.Namespace != "" {
				continue
			}
		}
		filtered = append(filtered, report)
	}
	return filtered
}
func (s *stubCacheService) GetReportsByRefs(refs []ReportRef) ([]Report, int) {
	byRef := make(map[ReportRef]Report)
	for _, reports := range s.reports {
		for _, report := range reports {
			report = ensureReportRef(report)
			byRef[report.Ref] = report
		}
	}
	items := make([]Report, 0, len(refs))
	missing := 0
	for _, ref := range refs {
		if report, ok := byRef[ref]; ok {
			items = append(items, report)
		} else {
			missing++
		}
	}
	return items, missing
}

func makeReport(name, cluster, ns, typ string, critical float64) Report {
	data := map[string]interface{}{
		"report": map[string]interface{}{
			"summary": map[string]interface{}{
				"criticalCount": critical,
			},
		},
	}
	return Report{Name: name, Cluster: cluster, Namespace: ns, Type: typ, Data: data, UpdatedAt: time.Now()}
}

func makeReportWithArtifact(name, cluster, ns, typ, repository string) Report {
	data := map[string]interface{}{
		"report": map[string]interface{}{
			"artifact": map[string]interface{}{
				"repository": repository,
			},
			"summary": map[string]interface{}{},
		},
	}
	return Report{Name: name, Cluster: cluster, Namespace: ns, Type: typ, Data: data, UpdatedAt: time.Now()}
}

func TestPaginateRefs_Empty(t *testing.T) {
	result := paginateRefs(nil, 1, 10)
	if len(result) != 0 {
		t.Fatalf("expected 0 got %d", len(result))
	}
}

func TestPaginateRefs_SinglePage(t *testing.T) {
	refs := make([]ReportRef, 5)
	result := paginateRefs(refs, 1, 10)
	if len(result) != 5 {
		t.Fatalf("expected 5 got %d", len(result))
	}
}

func TestPaginateRefs_SecondPage(t *testing.T) {
	refs := make([]ReportRef, 25)
	for i := range refs {
		refs[i].Name = fmt.Sprintf("r%d", i)
	}
	result := paginateRefs(refs, 2, 10)
	if len(result) != 10 {
		t.Fatalf("expected 10 got %d", len(result))
	}
	if result[0].Name != "r10" {
		t.Fatalf("expected r10 got %s", result[0].Name)
	}
}

func TestPaginateRefs_LastPagePartial(t *testing.T) {
	refs := make([]ReportRef, 25)
	result := paginateRefs(refs, 3, 10)
	if len(result) != 5 {
		t.Fatalf("expected 5 got %d", len(result))
	}
}

func TestPaginateRefs_OutOfBounds(t *testing.T) {
	refs := make([]ReportRef, 5)
	result := paginateRefs(refs, 10, 10)
	if len(result) != 0 {
		t.Fatalf("expected 0 got %d", len(result))
	}
}

func TestPaginateRefs_InvalidArguments(t *testing.T) {
	refs := make([]ReportRef, 5)
	if got := paginateRefs(refs, 0, 10); len(got) != 0 {
		t.Fatalf("expected empty result for page zero, got %d", len(got))
	}
	if got := paginateRefs(refs, 1, 0); len(got) != 0 {
		t.Fatalf("expected empty result for page size zero, got %d", len(got))
	}
}

func TestReportMatchesSearch_ByName(t *testing.T) {
	r := makeReport("my-deployment", "cluster1", "default", "vuln", 0)
	if !reportMatchesSearch(r, "my-dep") {
		t.Fatal("should match by name")
	}
}

func TestReportMatchesSearch_ByCluster(t *testing.T) {
	r := makeReport("deploy", "prod-cluster", "ns", "vuln", 0)
	if !reportMatchesSearch(r, "prod") {
		t.Fatal("should match by cluster")
	}
}

func TestReportMatchesSearch_ByNamespace(t *testing.T) {
	r := makeReport("deploy", "c1", "kube-system", "vuln", 0)
	if !reportMatchesSearch(r, "kube") {
		t.Fatal("should match by namespace")
	}
}

func TestReportMatchesSearch_ByArtifactRepository(t *testing.T) {
	r := makeReportWithArtifact("img", "c1", "ns", "vuln", "nginx/nginx")
	if !reportMatchesSearch(r, "nginx") {
		t.Fatal("should match by repository")
	}
}

func TestReportMatchesSearch_NoMatch(t *testing.T) {
	r := makeReport("deploy", "cluster", "ns", "vuln", 0)
	if reportMatchesSearch(r, "zzz-nomatch") {
		t.Fatal("should not match")
	}
}

func TestReportMatchesSearch_CaseInsensitive(t *testing.T) {
	r := makeReport("MyReport", "cluster", "ns", "vuln", 0)
	if !reportMatchesSearch(r, strings.ToLower("MyReport")) {
		t.Fatal("should match case-insensitively")
	}
}

func newQuerySvc(reports []Report, typeName string) QueryService {
	queryResultCache.Range(func(key string, _ SortedRefIndex) bool {
		queryResultCache.Delete(key)
		return true
	})
	stub := &stubCacheService{
		reports: map[string][]Report{typeName: reports},
	}
	return NewQueryService(stub)
}

func TestListReports_UserScopeExcludesClusterScopedAndOtherNamespaces(t *testing.T) {
	stub := &stubCacheService{reports: map[string][]Report{
		"vulnerabilityreports": {
			makeReport("allowed", "cluster-a", "team-a", "vulnerabilityreports", 1),
			makeReport("forbidden", "cluster-a", "team-b", "vulnerabilityreports", 1),
		},
		"clustervulnerabilityreports": {
			makeReport("cluster-report", "cluster-a", "", "clustervulnerabilityreports", 1),
		},
	}}
	svc := NewQueryService(stub)
	access := auth.NewAccessSnapshot(
		auth.UnrestrictedScope(),
		auth.NewScopeSnapshot([]auth.ScopeRule{{Cluster: "cluster-a", Namespaces: []string{"team-a"}}}),
	)

	result := svc.ListReports(ReportQuery{Type: "vulnerabilityreports", Page: 1, PageSize: 50, Access: access})
	if result.Total != 1 || len(result.Items) != 1 || result.Items[0].Name != "allowed" {
		t.Fatalf("restricted query returned total=%d items=%v", result.Total, result.Items)
	}
	clusterResult := svc.ListReports(ReportQuery{Type: "clustervulnerabilityreports", Page: 1, PageSize: 50, Access: access})
	if clusterResult.Total != 0 || len(clusterResult.Items) != 0 {
		t.Fatalf("restricted query returned cluster-scoped reports: %+v", clusterResult)
	}
}

func TestListReports_All(t *testing.T) {
	reports := []Report{
		makeReport("r1", "c", "ns", "vuln", 0),
		makeReport("r2", "c", "ns", "vuln", 2),
		makeReport("r3", "c", "ns", "vuln", 0),
	}
	svc := newQuerySvc(reports, "vuln")
	result := svc.ListReports(ReportQuery{Type: "vuln", Page: 1, PageSize: 50})
	if result.Total != 3 {
		t.Fatalf("expected total=3 got %d", result.Total)
	}
	if result.WithVulnerabilities != 1 {
		t.Fatalf("expected withVuln=1 got %d", result.WithVulnerabilities)
	}
	if len(result.Items) != 3 {
		t.Fatalf("expected 3 items got %d", len(result.Items))
	}
}

func TestListReports_OnlyVulnerable(t *testing.T) {
	reports := []Report{
		makeReport("r1", "c", "ns", "vuln", 0),
		makeReport("r2", "c", "ns", "vuln", 3),
		makeReport("r3", "c", "ns", "vuln", 0),
	}
	svc := newQuerySvc(reports, "vuln")
	result := svc.ListReports(ReportQuery{Type: "vuln", OnlyVulnerable: true, Page: 1, PageSize: 50})
	if result.Total != 1 {
		t.Fatalf("expected total=1 got %d", result.Total)
	}
	if result.Items[0].Name != "r2" {
		t.Fatalf("expected r2 got %s", result.Items[0].Name)
	}
}

func TestListReports_Search(t *testing.T) {
	reports := []Report{
		makeReport("alpha", "c", "ns", "vuln", 0),
		makeReport("beta", "c", "ns", "vuln", 0),
	}
	svc := newQuerySvc(reports, "vuln")
	result := svc.ListReports(ReportQuery{Type: "vuln", Search: "alp", Page: 1, PageSize: 50})
	if result.Total != 1 || result.Items[0].Name != "alpha" {
		t.Fatalf("expected alpha only, got %+v", result)
	}
}

func TestListReports_Pagination(t *testing.T) {
	var reports []Report
	for i := 0; i < 30; i++ {
		reports = append(reports, makeReport(fmt.Sprintf("r%02d", i), "c", "ns", "vuln", 0))
	}
	svc := newQuerySvc(reports, "vuln")
	result := svc.ListReports(ReportQuery{Type: "vuln", Page: 2, PageSize: 10})
	if result.Total != 30 {
		t.Fatalf("expected total=30 got %d", result.Total)
	}
	if len(result.Items) != 10 {
		t.Fatalf("expected 10 items on page 2 got %d", len(result.Items))
	}
}

func TestListReports_Empty(t *testing.T) {
	const emptyType = "empty-type-no-data"
	queryResultCache.Range(func(key string, _ SortedRefIndex) bool {
		queryResultCache.Delete(key)
		return true
	})
	svc := newQuerySvc(nil, emptyType)
	result := svc.ListReports(ReportQuery{Type: emptyType, Page: 1, PageSize: 50})
	if result.Total != 0 || len(result.Items) != 0 {
		t.Fatalf("expected empty result got %+v", result)
	}
}

func TestQueryResultCacheKey_Deterministic(t *testing.T) {
	q := ReportQuery{Type: "vuln", Cluster: "c", Namespaces: []string{"ns"}, Search: "foo", OnlyVulnerable: true, Page: 1, PageSize: 10}
	k1 := refIndexCacheKey(q, 5)
	k2 := refIndexCacheKey(q, 5)
	if k1 != k2 {
		t.Fatalf("cache key not deterministic: %s vs %s", k1, k2)
	}
}

func TestQueryResultCacheKey_VersionDistinct(t *testing.T) {
	q := ReportQuery{Type: "vuln", Page: 1, PageSize: 10}
	k1 := refIndexCacheKey(q, 1)
	k2 := refIndexCacheKey(q, 2)
	if k1 == k2 {
		t.Fatal("different versions should produce different cache keys")
	}
}

func TestRefIndexCacheKey_NormalizesNamespaces(t *testing.T) {
	q1 := ReportQuery{Type: "vuln", Namespaces: []string{"ns-b", "ns-a", "ns-a"}}
	q2 := ReportQuery{Type: "vuln", Namespaces: []string{"ns-a", "ns-b"}}
	if refIndexCacheKey(q1, 7) != refIndexCacheKey(q2, 7) {
		t.Fatal("equivalent namespace filters should share a cache key")
	}
}

func TestGetTrendsForScope_AggregatesAuthorizedFleetAndClusterReports(t *testing.T) {
	bucket := time.Now().UTC().Truncate(time.Hour)
	cache := &stubCacheService{trends: []TrendRecord{
		{Timestamp: bucket, Critical: 100},
		{Timestamp: bucket, Cluster: "prod", Critical: 100},
		{Timestamp: bucket, Cluster: "prod", Namespace: "team-a", Critical: 2, High: 3},
		{Timestamp: bucket, Cluster: "prod", Namespace: "team-b", Critical: 50},
		{Timestamp: bucket, Cluster: "prod", Namespace: auth.ClusterScopedNamespace, Critical: 7, High: 11},
	}}
	h := NewHandler(nil, cache, nil, NewQueryService(cache), nil, nil, nil)
	scope := auth.NewAccessSnapshot(
		auth.NewScopeSnapshot([]auth.ScopeRule{{Cluster: "prod", Namespaces: []string{"team-a", auth.ClusterScopedNamespace}}}),
		auth.UnrestrictedScope(),
	)

	got := h.getTrendsForScope("", 30, scope)
	if len(got) != 2 {
		t.Fatalf("got %d trends, want fleet and prod aggregates: %+v", len(got), got)
	}
	byCluster := make(map[string]TrendRecord, len(got))
	for _, trend := range got {
		byCluster[trend.Cluster] = trend
	}
	for _, cluster := range []string{"", "prod"} {
		trend, ok := byCluster[cluster]
		if !ok {
			t.Fatalf("missing %q aggregate in %+v", cluster, got)
		}
		if trend.Critical != 9 || trend.High != 14 || trend.Namespace != "" {
			t.Errorf("%q aggregate = %+v, want critical=9 high=14 without namespace", cluster, trend)
		}
	}

	clusterOnly := h.getTrendsForScope("prod", 30, scope)
	if len(clusterOnly) != 1 || clusterOnly[0].Cluster != "prod" || clusterOnly[0].Critical != 9 || clusterOnly[0].High != 14 {
		t.Fatalf("cluster trend = %+v, want one prod aggregate with authorized totals", clusterOnly)
	}
}
