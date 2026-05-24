package api

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

type stubCacheService struct {
	reports map[string][]Report
}

func (s *stubCacheService) Get(key string) (interface{}, bool)        { return nil, false }
func (s *stubCacheService) Items() map[string]interface{}             { return nil }
func (s *stubCacheService) ItemsByType(t string) map[string]interface{} { return nil }
func (s *stubCacheService) Set(key string, value interface{}, _ time.Duration) {}
func (s *stubCacheService) Delete(key string)                         {}
func (s *stubCacheService) DeleteReportEntry(_, _, _, _ string)       {}
func (s *stubCacheService) GetReportCount(_, _ string) (int, int)     { return 0, 0 }
func (s *stubCacheService) GetOverviewData(_ string) *ClusterOverview { return nil }
func (s *stubCacheService) GetTrends(_ string, _ int) []TrendRecord   { return nil }
func (s *stubCacheService) GetStats() map[string]interface{}          { return nil }
func (s *stubCacheService) GetReports(typeName, clusterFilter string, namespaceFilters []string) []Report {
	return s.reports[typeName]
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

func TestPaginateReports_Empty(t *testing.T) {
	result := paginateReports(nil, 1, 10)
	if len(result) != 0 {
		t.Fatalf("expected 0 got %d", len(result))
	}
}

func TestPaginateReports_SinglePage(t *testing.T) {
	reports := make([]Report, 5)
	result := paginateReports(reports, 1, 10)
	if len(result) != 5 {
		t.Fatalf("expected 5 got %d", len(result))
	}
}

func TestPaginateReports_SecondPage(t *testing.T) {
	reports := make([]Report, 25)
	for i := range reports {
		reports[i].Name = fmt.Sprintf("r%d", i)
	}
	result := paginateReports(reports, 2, 10)
	if len(result) != 10 {
		t.Fatalf("expected 10 got %d", len(result))
	}
	if result[0].Name != "r10" {
		t.Fatalf("expected r10 got %s", result[0].Name)
	}
}

func TestPaginateReports_LastPagePartial(t *testing.T) {
	reports := make([]Report, 25)
	result := paginateReports(reports, 3, 10)
	if len(result) != 5 {
		t.Fatalf("expected 5 got %d", len(result))
	}
}

func TestPaginateReports_OutOfBounds(t *testing.T) {
	reports := make([]Report, 5)
	result := paginateReports(reports, 10, 10)
	if len(result) != 0 {
		t.Fatalf("expected 0 got %d", len(result))
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
	stub := &stubCacheService{
		reports: map[string][]Report{typeName: reports},
	}
	return NewQueryService(stub)
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
	queryResultCache.Range(func(k, _ any) bool {
		if key, ok := k.(string); ok && len(key) > len(emptyType) && key[:len(emptyType)] == emptyType {
			queryResultCache.Delete(k)
		}
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
	k1 := queryResultCacheKey(q, 5)
	k2 := queryResultCacheKey(q, 5)
	if k1 != k2 {
		t.Fatalf("cache key not deterministic: %s vs %s", k1, k2)
	}
}

func TestQueryResultCacheKey_VersionDistinct(t *testing.T) {
	q := ReportQuery{Type: "vuln", Page: 1, PageSize: 10}
	k1 := queryResultCacheKey(q, 1)
	k2 := queryResultCacheKey(q, 2)
	if k1 == k2 {
		t.Fatal("different versions should produce different cache keys")
	}
}
