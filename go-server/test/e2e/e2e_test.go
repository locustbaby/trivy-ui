//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ---------------------------------------------------------------------------
// Minimal typed views over the trivy-ui HTTP API.
// ---------------------------------------------------------------------------

type apiEnvelope struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Error   *apiErrorBody   `json:"error"`
	Data    json.RawMessage `json:"data"`
}

type apiErrorBody struct {
	Type      string `json:"type"`
	RequestID string `json:"requestId"`
}

type reportRef struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Type      string `json:"type"`
}

type listData struct {
	Total               int         `json:"total"`
	WithVulnerabilities int         `json:"withVulnerabilities"`
	Page                int         `json:"page"`
	PageSize            int         `json:"pageSize"`
	HasNext             bool        `json:"hasNext"`
	Data                []reportRef `json:"data"`
}

type overviewData struct {
	TotalReports       int            `json:"total_reports"`
	SeverityTotals     map[string]int `json:"severity_totals"`
	ScanTypesBreakdown map[string]struct {
		Scanned  int `json:"scanned"`
		Failed   int `json:"failed"`
		Critical int `json:"critical"`
	} `json:"scan_types_breakdown"`
	TopVulnerableWorkloads []map[string]interface{} `json:"top_vulnerable_workloads"`
}

type clusterInfo struct {
	Name         string `json:"name"`
	SyncState    string `json:"syncState"`
	DataComplete bool   `json:"dataComplete"`
}

func apiGet(t testing.TB, path string) (int, apiEnvelope) {
	t.Helper()
	resp, err := http.Get(baseURL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	var env apiEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("GET %s: invalid JSON response: %v", path, err)
	}
	return resp.StatusCode, env
}

func expectOK(t testing.TB, path string) apiEnvelope {
	t.Helper()
	status, env := apiGet(t, path)
	if status != http.StatusOK || env.Code != 0 {
		t.Fatalf("GET %s: status=%d code=%d message=%q", path, status, env.Code, env.Message)
	}
	return env
}

func decodeList(t testing.TB, env apiEnvelope) listData {
	t.Helper()
	var data listData
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode list data: %v (%s)", err, string(env.Data))
	}
	return data
}

func walkAllPages(t testing.TB, typeName string, pageSize int) (listData, []string) {
	t.Helper()
	var all []string
	first := listData{}
	for page := 1; ; page++ {
		path := fmt.Sprintf("/api/v1/reports?type=%s&page=%d&pageSize=%d", typeName, page, pageSize)
		data := decodeList(t, expectOK(t, path))
		if page == 1 {
			first = data
			if data.Page != 1 || data.PageSize != pageSize {
				t.Fatalf("%s: echoed page/pageSize = %d/%d", typeName, data.Page, data.PageSize)
			}
		}
		wantHasNext := page*pageSize < data.Total
		if data.HasNext != wantHasNext {
			t.Fatalf("%s page %d: hasNext=%v, want %v (total=%d)", typeName, page, data.HasNext, wantHasNext, data.Total)
		}
		for _, item := range data.Data {
			key := item.Namespace + "/" + item.Name
			all = append(all, key)
		}
		if !data.HasNext {
			return first, all
		}
		if page > 500 {
			t.Fatalf("%s: pagination did not terminate", typeName)
		}
	}
}

// ---------------------------------------------------------------------------
// Ground truth read straight back from the kwok API server.
// ---------------------------------------------------------------------------

type seededReport struct {
	ref        reportRef
	summary    map[string]int // critical/high/medium/low counts (missing -> absent)
	hasSummary bool
}

type groundTruth struct {
	reports     []seededReport
	clusterName string
}

func countKey(summary interface{}) map[string]int {
	counts := make(map[string]int)
	m, ok := summary.(map[string]interface{})
	if !ok {
		return counts
	}
	for _, key := range []string{"criticalCount", "highCount", "mediumCount", "lowCount"} {
		switch v := m[key].(type) {
		case float64:
			counts[key] = int(v)
		case int:
			counts[key] = v
		case int64:
			counts[key] = int(v)
		}
	}
	return counts
}

func loadGroundTruth(t testing.TB) groundTruth {
	t.Helper()
	dc, err := dynamicClientFromEnv()
	if err != nil {
		t.Fatalf("dynamic client: %v", err)
	}
	set := gvrs()
	ctx := context.Background()
	gt := groundTruth{}

	listNamespaced := func(resource, typ string) {
		var items *unstructured.UnstructuredList
		items, err = dc.Resource(set.byName(resource)).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatalf("list %s from apiserver: %v", resource, err)
		}
		for _, item := range items.Items {
			s := item.UnstructuredContent()["report"]
			var raw interface{}
			if m, ok := s.(map[string]interface{}); ok {
				raw = m["summary"]
			}
			gt.reports = append(gt.reports, seededReport{
				ref: reportRef{
					Namespace: item.GetNamespace(),
					Name:      item.GetName(),
					Type:      typ,
				},
				summary:    countKey(raw),
				hasSummary: raw != nil,
			})
		}
	}
	listNamespaced("vulnerabilityreports", "vulnerabilityreports")
	listNamespaced("configauditreports", "configauditreports")
	listNamespaced("exposedsecretreports", "exposedsecretreports")

	clusterItems, err := dc.Resource(set.byName("clustervulnerabilityreports")).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list clustervulnerabilityreports from apiserver: %v", err)
	}
	for _, item := range clusterItems.Items {
		s := item.UnstructuredContent()["report"]
		var raw interface{}
		if m, ok := s.(map[string]interface{}); ok {
			raw = m["summary"]
		}
		gt.reports = append(gt.reports, seededReport{
			ref:        reportRef{Namespace: "", Name: item.GetName(), Type: "clustervulnerabilityreports"},
			summary:    countKey(raw),
			hasSummary: raw != nil,
		})
	}

	env := expectOK(t, "/api/v1/clusters")
	var clusters []clusterInfo
	if err := json.Unmarshal(env.Data, &clusters); err != nil {
		t.Fatalf("decode clusters: %v (%s)", err, string(env.Data))
	}
	if len(clusters) == 0 {
		t.Fatal("no clusters reported by trivy-ui")
	}
	gt.clusterName = clusters[0].Name
	return gt
}

func (gt groundTruth) byType(typ string) []seededReport {
	var out []seededReport
	for _, r := range gt.reports {
		if r.ref.Type == typ {
			out = append(out, r)
		}
	}
	return out
}

func (gt groundTruth) totals() (total int, sev map[string]int) {
	sev = map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for _, r := range gt.reports {
		total++
		for k, v := range r.summary {
			switch k {
			case "criticalCount":
				sev["critical"] += v
			case "highCount":
				sev["high"] += v
			case "mediumCount":
				sev["medium"] += v
			case "lowCount":
				sev["low"] += v
			}
		}
	}
	return total, sev
}

func (r seededReport) isVulnerable() bool {
	return r.summary["criticalCount"] > 0 || r.summary["highCount"] > 0 ||
		r.summary["mediumCount"] > 0 || r.summary["lowCount"] > 0
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

var allTypes = []string{
	"vulnerabilityreports",
	"configauditreports",
	"exposedsecretreports",
	"clustervulnerabilityreports",
}

func TestClustersDiscoveredAndSynced(t *testing.T) {
	env := expectOK(t, "/api/v1/clusters")
	var clusters []clusterInfo
	if err := json.Unmarshal(env.Data, &clusters); err != nil {
		t.Fatalf("decode clusters: %v", err)
	}
	found := false
	for _, c := range clusters {
		if c.DataComplete && c.SyncState != "" {
			found = true
			t.Logf("cluster %q syncState=%q", c.Name, c.SyncState)
		}
	}
	if !found {
		t.Fatalf("expected at least one complete cluster, got %+v", clusters)
	}
}

func TestReportTypesDiscovered(t *testing.T) {
	env := expectOK(t, "/api/v1/report-types")
	raw, _ := json.Marshal(env.Data)
	t.Logf("report types: %s", raw)
	for _, typ := range allTypes {
		if !strings.Contains(string(raw), typ) {
			t.Errorf("report type %q not discovered", typ)
		}
	}
}

func TestPaginationMatchesAPIServerGroundTruth(t *testing.T) {
	gt := loadGroundTruth(t)
	for _, typ := range allTypes {
		want := gt.byType(typ)
		first, walked := walkAllPages(t, typ, 7)
		if first.Total != len(want) {
			t.Errorf("%s: total=%d, want %d (from apiserver)", typ, first.Total, len(want))
		}
		if len(walked) != len(want) {
			t.Errorf("%s: pagination walk collected %d items across pages, want %d", typ, len(walked), len(want))
		}
		seen := make(map[string]bool, len(walked))
		for _, key := range walked {
			if seen[key] {
				t.Errorf("%s: duplicate item in walk: %s", typ, key)
			}
			seen[key] = true
		}
		if len(seen) != len(want) {
			t.Errorf("%s: %d unique items after full walk, want %d", typ, len(seen), len(want))
		}
	}
}

// forceIndexRebuild creates and deletes a probe report so the server-side
// cache generation is bumped (informer delete events invalidate the index),
// guaranteeing subsequent walks exercise real index rebuilds instead of
// replaying one cached snapshot.
func forceIndexRebuild(t testing.TB) {
	t.Helper()
	dc, err := dynamicClientFromEnv()
	if err != nil {
		t.Fatalf("dynamic client: %v", err)
	}
	set := gvrs()
	ctx, cancel := context.WithTimeout(context.Background(), informerTimeout)
	defer cancel()

	name := "rebuild-probe-report"
	baseline := decodeList(t, expectOK(t, "/api/v1/reports?type=vulnerabilityreports&pageSize=1")).Total

	payload := reportEnvelope("vuln", 0, summaryMap(severityCounts{}), []interface{}{})
	obj := cr(group+"/"+version, "VulnerabilityReport", name, "team-a", payload)
	if _, err := dc.Resource(set.Vulns).Namespace("team-a").Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create rebuild probe: %v", err)
	}
	for ctx.Err() == nil {
		if got := decodeList(t, expectOK(t, "/api/v1/reports?type=vulnerabilityreports&pageSize=1")).Total; got == baseline+1 {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err := dc.Resource(set.Vulns).Namespace("team-a").Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete rebuild probe: %v", err)
	}
	for ctx.Err() == nil {
		if got := decodeList(t, expectOK(t, "/api/v1/reports?type=vulnerabilityreports&pageSize=1")).Total; got == baseline {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatal("rebuild probe never disappeared after deletion")
}

func TestOrderStableAcrossRefreshesAndPageSizes(t *testing.T) {
	gt := loadGroundTruth(t)
	typ := "vulnerabilityreports"
	if len(gt.byType(typ)) < 10 {
		t.Fatalf("not enough %s seeded for stability test", typ)
	}

	_, run1 := walkAllPages(t, typ, 13)

	for i := 0; i < 2; i++ {
		// Force at least two real cache invalidations + index rebuilds so the
		// order-stability claim holds across refreshes, not just cache replays.
		forceIndexRebuild(t)
		_, runN := walkAllPages(t, typ, 13)
		if fmt.Sprint(run1) != fmt.Sprint(runN) {
			t.Fatalf("%s: order changed between refresh %d:\nfirst: %v\nlater: %v", typ, i+2, run1, runN)
		}
	}

	// A different page size must yield the exact same global order.
	_, runBigPages := walkAllPages(t, typ, 50)
	if fmt.Sprint(run1) != fmt.Sprint(runBigPages) {
		t.Fatalf("%s: order differs between pageSize=13 and pageSize=50", typ)
	}

	// Sorted output must equal lexicographic sort of the sort keys we can
	// derive (namespace/name within one cluster and type).
	sorted := append([]string(nil), run1...)
	sort.Strings(sorted)
	if fmt.Sprint(sorted) != fmt.Sprint(run1) {
		t.Fatalf("%s: sequence not globally sorted:\n%v\nvs\n%v", typ, run1, sorted)
	}
}

func TestFiltersMatchGroundTruth(t *testing.T) {
	gt := loadGroundTruth(t)

	// onlyVulnerable
	vulnCount := 0
	for _, r := range gt.byType("vulnerabilityreports") {
		if r.isVulnerable() {
			vulnCount++
		}
	}
	data := decodeList(t, expectOK(t, "/api/v1/reports?type=vulnerabilityreports&onlyVulnerable=true&pageSize=200"))
	if data.Total != vulnCount {
		t.Errorf("onlyVulnerable total=%d, want %d", data.Total, vulnCount)
	}

	// namespace filter (single + multi + spaces)
	nsA := 0
	for _, r := range gt.byType("vulnerabilityreports") {
		if r.ref.Namespace == "team-a" {
			nsA++
		}
	}
	data = decodeList(t, expectOK(t, "/api/v1/reports?type=vulnerabilityreports&namespace=team-a&pageSize=200"))
	if data.Total != nsA {
		t.Errorf("namespace=team-a total=%d, want %d", data.Total, nsA)
	}
	teamAB := nsA + countOfNS(gt, "team-b")
	data = decodeList(t, expectOK(t, "/api/v1/reports?type=vulnerabilityreports&namespace=team-a,+team-b&pageSize=200"))
	if data.Total != teamAB {
		t.Errorf("multi-namespace total=%d, want %d", data.Total, teamAB)
	}

	// search matches name substring computed against ground truth names
	searchHits := 0
	for _, r := range gt.byType("vulnerabilityreports") {
		if strings.Contains(r.ref.Name, "web-frontend") {
			searchHits++
		}
	}
	data = decodeList(t, expectOK(t, "/api/v1/reports?type=vulnerabilityreports&search=web-frontend&pageSize=200"))
	if data.Total != searchHits {
		t.Errorf("search total=%d, want %d", data.Total, searchHits)
	}

	// unknown namespace yields zero results but a healthy envelope
	data = decodeList(t, expectOK(t, "/api/v1/reports?type=vulnerabilityreports&namespace=no-such-ns"))
	if data.Total != 0 || len(data.Data) != 0 || data.HasNext {
		t.Errorf("unknown namespace should return empty result, got %+v", data)
	}
}

func countOfNS(gt groundTruth, ns string) int {
	n := 0
	for _, r := range gt.byType("vulnerabilityreports") {
		if r.ref.Namespace == ns {
			n++
		}
	}
	return n
}

func TestOverviewAggregatesEqualGroundTruth(t *testing.T) {
	gt := loadGroundTruth(t)
	totalReports, sev := gt.totals()

	env := expectOK(t, "/api/v1/overview")
	var ov overviewData
	if err := json.Unmarshal(env.Data, &ov); err != nil {
		t.Fatalf("decode overview: %v (%s)", err, string(env.Data))
	}
	if ov.TotalReports != totalReports {
		t.Errorf("overview total_reports=%d, want %d", ov.TotalReports, totalReports)
	}
	for k, want := range sev {
		if got := ov.SeverityTotals[k]; got != want {
			t.Errorf("severity_totals.%s=%d, want %d", k, got, want)
		}
	}
	for _, typ := range allTypes {
		tb, ok := ov.ScanTypesBreakdown["report:"+typ]
		if !ok {
			// try alternative keying without prefix
			tb, ok = ov.ScanTypesBreakdown[typ]
		}
		if !ok {
			t.Errorf("scan_types_breakdown missing entry for %s (keys: %v)", typ, keysOf(ov.ScanTypesBreakdown))
			continue
		}
		if tb.Scanned != len(gt.byType(typ)) {
			t.Errorf("scan_types_breakdown[%s].scanned=%d, want %d", typ, tb.Scanned, len(gt.byType(typ)))
		}
	}
}

func keysOf(m map[string]struct {
	Scanned  int `json:"scanned"`
	Failed   int `json:"failed"`
	Critical int `json:"critical"`
}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestDetailEndpointReturnsCRContent(t *testing.T) {
	gt := loadGroundTruth(t)
	var target *seededReport
	for i := range gt.reports {
		r := gt.reports[i]
		if r.ref.Type == "vulnerabilityreports" && r.hasSummary && r.summary["criticalCount"] > 0 {
			target = &gt.reports[i]
			break
		}
	}
	if target == nil {
		t.Fatal("no suitable vulnerabilityreport found for detail check")
	}

	path := fmt.Sprintf("/api/v1/reports/%s/%s/%s/%s",
		gt.clusterName, target.ref.Type, target.ref.Namespace, target.ref.Name)
	env := expectOK(t, path)
	raw, _ := json.Marshal(env.Data)
	var detail struct {
		Ref  reportRef `json:"ref"`
		Data struct {
			Report struct {
				Summary map[string]interface{} `json:"summary"`
			} `json:"report"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &detail); err != nil {
		t.Fatalf("decode detail: %v (%s)", err, string(raw))
	}
	if detail.Ref.Name != target.ref.Name || detail.Ref.Namespace != target.ref.Namespace {
		t.Errorf("detail ref mismatch: %+v", detail.Ref)
	}
	crit, _ := detail.Data.Report.Summary["criticalCount"].(float64)
	if int(crit) != target.summary["criticalCount"] {
		t.Errorf("detail summary.criticalCount=%.0f, want %d", crit, target.summary["criticalCount"])
	}
}

func TestErrorMatrix(t *testing.T) {
	gt := loadGroundTruth(t)

	// Unknown report type on the detail route -> 400 VALIDATION_FAILED.
	status, env := apiGet(t, fmt.Sprintf("/api/v1/reports/%s/nosuchtype/team-a/whatever", gt.clusterName))
	if status != http.StatusBadRequest || env.Error == nil || env.Error.Type != "VALIDATION_FAILED" {
		t.Errorf("unknown type: status=%d error=%+v, want 400 VALIDATION_FAILED", status, env.Error)
	}

	// Missing type parameter -> 400 VALIDATION_FAILED.
	status, env = apiGet(t, "/api/v1/reports?page=1")
	if status != http.StatusBadRequest || env.Error == nil || env.Error.Type != "VALIDATION_FAILED" {
		t.Errorf("missing type param: status=%d error=%+v, want 400 VALIDATION_FAILED", status, env.Error)
	}

	// Detail against an unknown cluster -> 403 ACCESS_DENIED: the data-access
	// source scope is built from initialized clusters, so an unknown cluster
	// fails the access check before the cluster-client lookup (this also
	// avoids leaking which clusters exist).
	status, env = apiGet(t, "/api/v1/reports/no-such-cluster/vulnerabilityreports/team-a/whatever")
	if status != http.StatusForbidden || env.Error == nil || env.Error.Type != "ACCESS_DENIED" {
		t.Errorf("unknown cluster: status=%d error=%+v, want 403 ACCESS_DENIED", status, env.Error)
	}

	// Detail of a nonexistent report in a real cluster -> 503 PROVIDER_UNAVAILABLE.
	status, env = apiGet(t, fmt.Sprintf("/api/v1/reports/%s/vulnerabilityreports/team-a/definitely-not-here", gt.clusterName))
	if status != http.StatusServiceUnavailable || env.Error == nil {
		t.Errorf("missing report: status=%d error=%+v, want 503 with error envelope", status, env.Error)
	}

	// Invalid paging params degrade to defaults instead of erroring/breaking.
	data := decodeList(t, expectOK(t, "/api/v1/reports?type=vulnerabilityreports&page=-3&pageSize=9999"))
	if data.Page != 1 || data.PageSize != 50 {
		t.Errorf("invalid params echo page/pageSize=%d/%d, want 1/50 fallback", data.Page, data.PageSize)
	}

	// Out-of-range page returns empty data but the correct total.
	full := decodeList(t, expectOK(t, "/api/v1/reports?type=vulnerabilityreports&page=9999&pageSize=10"))
	base := decodeList(t, expectOK(t, "/api/v1/reports?type=vulnerabilityreports&pageSize=1"))
	if full.Total != base.Total || len(full.Data) != 0 || full.HasNext {
		t.Errorf("out-of-range page: total=%d items=%d hasNext=%v (real total=%d)",
			full.Total, len(full.Data), full.HasNext, base.Total)
	}
}

func TestLiveUpdatePropagatesThroughInformer(t *testing.T) {
	dc, err := dynamicClientFromEnv()
	if err != nil {
		t.Fatalf("dynamic client: %v", err)
	}
	set := gvrs()
	ctx, cancel := context.WithTimeout(context.Background(), informerTimeout)
	defer cancel()

	before := decodeList(t, expectOK(t, "/api/v1/reports?type=vulnerabilityreports&pageSize=1")).Total

	name := "live-update-probe-report"
	payload := reportEnvelope("vuln", 42, summaryMap(severityCounts{critical: 9}), []interface{}{})
	obj := cr(group+"/"+version, "VulnerabilityReport", name, "team-a", payload)

	if _, err := dc.Resource(set.Vulns).Namespace("team-a").Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create probe CR: %v", err)
	}
	defer dc.Resource(set.Vulns).Namespace("team-a").Delete(context.Background(), name, metav1.DeleteOptions{})

	created := false
	for ctx.Err() == nil {
		data := decodeList(t, expectOK(t, "/api/v1/reports?type=vulnerabilityreports&search="+name+"&pageSize=10"))
		if data.Total == 1 {
			created = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !created {
		t.Fatal("newly created report never appeared via the informer watch")
	}

	after := -1
	for ctx.Err() == nil {
		after = decodeList(t, expectOK(t, "/api/v1/reports?type=vulnerabilityreports&pageSize=1")).Total
		if after == before+1 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if after != before+1 {
		t.Fatalf("list total after create = %d, want %d", after, before+1)
	}

	// Deletion must also propagate.
	if err := dc.Resource(set.Vulns).Namespace("team-a").Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete probe CR: %v", err)
	}
	gone := false
	for ctx.Err() == nil {
		data := decodeList(t, expectOK(t, "/api/v1/reports?type=vulnerabilityreports&search="+name+"&pageSize=10"))
		if data.Total == 0 {
			gone = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !gone {
		t.Fatal("deleted report still visible through the API")
	}
}
