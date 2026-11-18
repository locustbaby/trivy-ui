package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type summaryCache struct {
	stubCacheService
	summaries []Report
}

func (s *summaryCache) ReportSummaries() []Report { return s.summaries }

func finding(id, severity, pkg, installed, fixed string) []interface{} {
	return []interface{}{id, severity, pkg, installed, fixed, "title of " + id}
}

func vulnReport(namespace, rsName, container, image string, scanned time.Time, summary map[string]interface{}, findings ...[]interface{}) Report {
	report := testReport("nuc", namespace, "vulnerabilityreports", "replicaset-"+rsName+"-"+container, rsName, summary, nil)
	data := report.Data.(map[string]interface{})
	parts := strings.SplitN(image, ":", 2)
	data["report"].(map[string]interface{})["artifact"] = map[string]interface{}{"repository": parts[0], "tag": parts[1]}
	data["report"].(map[string]interface{})["registry"] = map[string]interface{}{"server": "index.docker.io"}
	data["report"].(map[string]interface{})["updateTimestamp"] = scanned.UTC().Format(time.RFC3339)
	list := make([]interface{}, len(findings))
	for i, f := range findings {
		list[i] = f
	}
	data["derived"] = map[string]interface{}{"version": 2, "findings": list, "fixable": map[string]interface{}{"critical": 1}}
	return report
}

func viewsHandler(reports ...Report) *Handler {
	cache := &summaryCache{summaries: reports}
	return NewHandler(nil, cache, nil, NewQueryService(cache), nil, nil, nil)
}

func getJSON(t *testing.T, handler http.HandlerFunc, url string) map[string]interface{} {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler(recorder, httptest.NewRequest(http.MethodGet, url, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", url, recorder.Code, recorder.Body.String())
	}
	var response struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response.Data
}

func viewsFixture() []Report {
	now := time.Now()
	return []Report{
		vulnReport("default", "web-7d9f6b5c4", "app", "library/nginx:1.27", now, counts(1, 1, 0, 0, 0),
			finding("CVE-1", "critical", "openssl", "3.0.1", "3.0.9"),
			finding("CVE-2", "high", "zlib", "1.2", "")),
		vulnReport("default", "api-6c8b7d5f9", "app", "library/nginx:1.27", now, counts(1, 0, 0, 0, 0),
			finding("CVE-1", "critical", "openssl", "3.0.1", "3.0.9")),
		vulnReport("media", "db-5f69475449", "db", "library/postgres:15", now.Add(-100*time.Hour), counts(0, 0, 1, 0, 0),
			finding("CVE-3", "medium", "libxml2", "2.9", "")),
	}
}

func TestGetVulnerabilitiesGroupsByID(t *testing.T) {
	h := viewsHandler(viewsFixture()...)
	data := getJSON(t, h.GetVulnerabilities, "/api/v1/vulnerabilities?cluster=nuc")
	items := data["items"].([]interface{})
	if data["total"] != float64(3) || len(items) != 3 {
		t.Fatalf("total = %v", data["total"])
	}
	first := items[0].(map[string]interface{})
	if first["id"] != "CVE-1" || first["workloads"] != float64(2) || first["images"] != float64(1) || first["fixable"] != true {
		t.Fatalf("CVE-1 should affect two workloads running one image: %v", first)
	}
	occurrence := first["occurrences"].([]interface{})[0].(map[string]interface{})
	if occurrence["workload"] != "api" || occurrence["fixed"] != "3.0.9" || occurrence["image"] != "index.docker.io/library/nginx:1.27" {
		t.Fatalf("occurrence = %v", occurrence)
	}

	fixable := getJSON(t, h.GetVulnerabilities, "/api/v1/vulnerabilities?fixable=true")
	if fixable["total"] != float64(1) {
		t.Fatalf("only CVE-1 has a fix: %v", fixable["total"])
	}
	bySeverity := getJSON(t, h.GetVulnerabilities, "/api/v1/vulnerabilities?severity=medium,high")
	if bySeverity["total"] != float64(2) {
		t.Fatalf("severity filter: %v", bySeverity["total"])
	}
	byWorkload := getJSON(t, h.GetVulnerabilities, "/api/v1/vulnerabilities?search=postgres")
	if byWorkload["total"] != float64(1) {
		t.Fatalf("search by image: %v", byWorkload["total"])
	}
	byNamespace := getJSON(t, h.GetVulnerabilities, "/api/v1/vulnerabilities?namespace=media")
	if byNamespace["total"] != float64(1) {
		t.Fatalf("namespace filter: %v", byNamespace["total"])
	}
	limited := getJSON(t, h.GetVulnerabilities, "/api/v1/vulnerabilities?limit=1")
	if limited["truncated"] != true || len(limited["items"].([]interface{})) != 1 {
		t.Fatalf("limit: %v", limited)
	}
}

func TestGetImagesCountsEachImageOnce(t *testing.T) {
	h := viewsHandler(viewsFixture()...)
	data := getJSON(t, h.GetImages, "/api/v1/images")
	items := data["items"].([]interface{})
	if len(items) != 2 {
		t.Fatalf("two distinct images expected: %v", items)
	}
	nginx := items[0].(map[string]interface{})
	if nginx["image"] != "index.docker.io/library/nginx:1.27" || len(nginx["workloads"].([]interface{})) != 2 || nginx["critical"] != float64(1) {
		t.Fatalf("nginx runs in two workloads but is one image: %v", nginx)
	}
}

func TestListItemsLeaveOutFindings(t *testing.T) {
	reports := viewsFixture()
	cache := &summaryCache{stubCacheService: stubCacheService{reports: map[string][]Report{"vulnerabilityreports": reports}}, summaries: reports}
	h := NewHandler(nil, cache, nil, NewQueryService(cache), nil, nil, nil)
	recorder := httptest.NewRecorder()
	h.GetReportsV1(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/reports?type=vulnerabilityreports&sort=severity", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("%d %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if strings.Contains(body, "CVE-1") || strings.Contains(body, `"findings"`) {
		t.Fatal("list responses must not carry the compact findings")
	}
	if !strings.Contains(body, `"fixable"`) {
		t.Fatal("list responses keep the other derived counts")
	}
	if _, ok := reports[0].Data.(map[string]interface{})["derived"].(map[string]interface{})["findings"]; !ok {
		t.Fatal("stripping must not modify the cached report")
	}

	recorder = httptest.NewRecorder()
	h.GetReportsV1(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/reports?type=vulnerabilityreports&sort=bogus", nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown sort mode: %d", recorder.Code)
	}
}

func TestSortReports(t *testing.T) {
	now := time.Now()
	make := func(name string, summary map[string]interface{}, fixableHigh int, scanned time.Time) Report {
		report := testReport("nuc", "default", "vulnerabilityreports", name, name, summary, map[string]interface{}{
			"version": 2, "fixable": map[string]interface{}{"high": fixableHigh},
		})
		report.Data.(map[string]interface{})["report"].(map[string]interface{})["updateTimestamp"] = scanned.UTC().Format(time.RFC3339)
		report.SortKey = name
		return report
	}
	reports := []Report{
		make("a", counts(0, 5, 0, 0, 0), 5, now),
		make("b", counts(1, 0, 0, 0, 0), 0, now.Add(-time.Hour)),
		make("c", counts(0, 5, 9, 0, 0), 1, now.Add(-2*time.Hour)),
	}
	names := func() string {
		out := ""
		for _, report := range reports {
			out += report.Name
		}
		return out
	}
	sortReports(reports, "severity")
	if names() != "bca" {
		t.Fatalf("severity: %s", names())
	}
	sortReports(reports, "fixable")
	if names() != "acb" {
		t.Fatalf("fixable: %s", names())
	}
	sortReports(reports, "scanned")
	if names() != "cba" {
		t.Fatalf("scanned (oldest first): %s", names())
	}
	sortReports(reports, "")
	if names() != "abc" {
		t.Fatalf("name: %s", names())
	}
}

func TestAggregateOverviewCountsStaleReports(t *testing.T) {
	ConfigureScanStaleAfter(72 * time.Hour)
	reports := viewsFixture()
	overview := aggregateOverview(reports, nil, registryWorkloadResolver(nil))
	if overview.StaleReports != 1 || overview.StaleAfterHours != 72 {
		t.Fatalf("stale=%d after=%d", overview.StaleReports, overview.StaleAfterHours)
	}
}
