package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// parseQueryParams: valid, invalid and boundary inputs must all degrade to a
// safe default instead of producing page=0 or an unbounded pageSize.
// ---------------------------------------------------------------------------

func TestParseQueryParams_Defaults(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/reports?type=x", nil)
	h := &Handler{}
	cluster, namespaces, page, pageSize := h.parseQueryParams(r)
	if cluster != "" || len(namespaces) != 0 {
		t.Fatalf("expected no filters, got cluster=%q namespaces=%v", cluster, namespaces)
	}
	if page != 1 || pageSize != 50 {
		t.Fatalf("expected page=1 pageSize=50, got page=%d pageSize=%d", page, pageSize)
	}
}

func TestParseQueryParams_ValidValues(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/reports?type=x&cluster=prod&namespace=a,+b%20&page=3&pageSize=25", nil)
	h := &Handler{}
	cluster, namespaces, page, pageSize := h.parseQueryParams(r)
	if cluster != "prod" {
		t.Fatalf("cluster = %q", cluster)
	}
	if len(namespaces) != 2 || namespaces[0] != "a" || namespaces[1] != "b" {
		t.Fatalf("namespaces = %v, want trimmed [a b]", namespaces)
	}
	if page != 3 || pageSize != 25 {
		t.Fatalf("page=%d pageSize=%d", page, pageSize)
	}
}

func TestParseQueryParams_InvalidPageFallsBackToDefault(t *testing.T) {
	h := &Handler{}
	for _, p := range []string{"0", "-5", "abc", ""} {
		url := "/api/v1/reports?type=x"
		if p != "" {
			url += "&page=" + p
		}
		r := httptest.NewRequest(http.MethodGet, url, nil)
		_, _, page, _ := h.parseQueryParams(r)
		if page != 1 {
			t.Fatalf("page param %q: expected fallback to 1, got %d", p, page)
		}
	}
}

func TestParseQueryParams_InvalidPageSizeFallsBackToDefault(t *testing.T) {
	h := &Handler{}
	// Zero, negative, non-numeric and above-limit sizes must never reach the
	// query layer; above 200 the value is rejected entirely (falls back to 50).
	for _, ps := range []string{"0", "-3", "abc", "201", "100000"} {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/reports?type=x&pageSize="+ps, nil)
		_, _, _, pageSize := h.parseQueryParams(r)
		if pageSize != 50 {
			t.Fatalf("pageSize param %q: expected fallback to 50, got %d", ps, pageSize)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/reports?type=x&pageSize=200", nil)
	if _, _, _, pageSize := h.parseQueryParams(r); pageSize != 200 {
		t.Fatalf("pageSize=200 should be accepted at the boundary, got %d", pageSize)
	}
}

// ---------------------------------------------------------------------------
// hasVulnerabilities / extractSummaryCounts: numeric variants coming from
// JSON decoding (float64), direct construction (int) and cache snapshots
// (int64) must all be recognised.
// ---------------------------------------------------------------------------

func summaryReport(summary map[string]interface{}) Report {
	return Report{Data: map[string]interface{}{
		"report": map[string]interface{}{"summary": summary},
	}}
}

func TestHasVulnerabilities_NumericVariants(t *testing.T) {
	h := &Handler{}
	cases := []struct {
		name    string
		report  Report
		wantHas bool
	}{
		{"float64 positive", summaryReport(map[string]interface{}{"criticalCount": float64(1)}), true},
		{"float64 zero", summaryReport(map[string]interface{}{"criticalCount": float64(0)}), false},
		{"int positive", summaryReport(map[string]interface{}{"highCount": 2}), true},
		{"int zero", summaryReport(map[string]interface{}{"highCount": 0}), false},
		{"int64 positive", summaryReport(map[string]interface{}{"mediumCount": int64(3)}), true},
		{"int64 zero", summaryReport(map[string]interface{}{"lowCount": int64(0)}), false},
		{"empty summary", summaryReport(map[string]interface{}{}), false},
		{"missing summary", Report{Data: map[string]interface{}{"report": map[string]interface{}{}}}, false},
		{"nil data", Report{}, false},
	}
	for _, tc := range cases {
		if got := h.hasVulnerabilities(tc.report); got != tc.wantHas {
			t.Errorf("%s: hasVulnerabilities = %v, want %v", tc.name, got, tc.wantHas)
		}
	}
}

func TestExtractSummaryCounts_NumericVariants(t *testing.T) {
	report := summaryReport(map[string]interface{}{
		"criticalCount": float64(4),
		"highCount":     5,
		"mediumCount":   int64(6),
		"lowCount":      7.9,
	})
	critical, high, medium, low := extractSummaryCounts(report)
	if critical != 4 || high != 5 || medium != 6 || low != 7 {
		t.Fatalf("got (%d,%d,%d,%d), want (4,5,6,7)", critical, high, medium, low)
	}
	if c, h2, m, l := extractSummaryCounts(Report{}); c != 0 || h2 != 0 || m != 0 || l != 0 {
		t.Fatalf("nil data should yield zeros, got (%d,%d,%d,%d)", c, h2, m, l)
	}
}

// ---------------------------------------------------------------------------
// decodeReportValue round-trips.
// ---------------------------------------------------------------------------

func TestDecodeReportValue_PassthroughAndConversion(t *testing.T) {
	original := Report{Type: "t", Cluster: "c", Namespace: "ns", Name: "n"}
	got, ok := decodeReportValue(original)
	if !ok || got.Name != "n" {
		t.Fatalf("Report passthrough failed: ok=%v got=%+v", ok, got)
	}

	asMap := map[string]interface{}{"type": "t", "cluster": "c", "namespace": "ns", "name": "n"}
	got, ok = decodeReportValue(asMap)
	if !ok || got.Cluster != "c" || got.Namespace != "ns" {
		t.Fatalf("map conversion failed: ok=%v got=%+v", ok, got)
	}

	if _, ok := decodeReportValue("not-a-report"); ok {
		t.Fatal("expected failure for unsupported value")
	}
}

// ---------------------------------------------------------------------------
// HTTP-level behaviour of GET /api/v1/reports using the stub cache service:
// response envelope shape, pagination boundaries, filters and error paths.
// ---------------------------------------------------------------------------

func newReportsHandler(reports map[string][]Report) *Handler {
	return NewHandler(nil, &stubCacheService{reports: reports}, nil, NewQueryService(&stubCacheService{reports: reports}), nil, nil, nil)
}

func decodeResponse(t *testing.T, rec *httptest.ResponseRecorder) Response {
	t.Helper()
	var resp Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v\nbody: %s", err, rec.Body.String())
	}
	return resp
}

func TestGetReportsV1_MissingTypeParameter(t *testing.T) {
	h := newReportsHandler(map[string][]Report{})
	rec := httptest.NewRecorder()
	h.GetReportsV1(rec, httptest.NewRequest(http.MethodGet, "/api/v1/reports", nil))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	resp := decodeResponse(t, rec)
	if resp.Code != CodeError {
		t.Fatalf("body code = %d, want %d", resp.Code, CodeError)
	}
	if resp.Error == nil || resp.Error.Type != string(ErrValidationFailed) {
		t.Fatalf("error.type = %+v, want %s", resp.Error, ErrValidationFailed)
	}
}

func TestGetReportsV1_PaginationWalkCoversAllItemsExactlyOnce(t *testing.T) {
	reports := make([]Report, 0, 45)
	for i := 0; i < 45; i++ {
		name := fmt.Sprintf("workload-%03d", i)
		ns := "team-a"
		if i%3 == 1 {
			ns = "team-b"
		} else if i%3 == 2 {
			ns = "team-c"
		}
		reports = append(reports, Report{
			Type: "vulns", Cluster: "kwok", Namespace: ns, Name: name,
			Data: map[string]interface{}{"report": map[string]interface{}{"summary": map[string]interface{}{
				"criticalCount": float64(i % 4),
			}}},
			UpdatedAt: time.Now(),
		})
	}
	h := newReportsHandler(map[string][]Report{"vulns-walk": reports})

	seen := make(map[string]int)
	var ordered []string
	page := 1
	total := -1
	withVuln := -1
	for {
		rec := httptest.NewRecorder()
		h.GetReportsV1(rec, httptest.NewRequest(http.MethodGet,
			fmt.Sprintf("/api/v1/reports?type=vulns-walk&page=%d&pageSize=10", page), nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("page %d status = %d body=%s", page, rec.Code, rec.Body.String())
		}
		resp := decodeResponse(t, rec)
		dataBytes, _ := json.Marshal(resp.Data)
		var paginated PaginatedResponse
		if err := json.Unmarshal(dataBytes, &paginated); err != nil {
			t.Fatalf("unexpected data payload: %s", dataBytes)
		}
		total = paginated.Total
		withVuln = paginated.WithVulnerabilities
		if paginated.Page != page || paginated.PageSize != 10 {
			t.Fatalf("echoed page/pageSize = %d/%d", paginated.Page, paginated.PageSize)
		}
		wantHasNext := page*10 < total
		if paginated.HasNext != wantHasNext {
			t.Fatalf("page %d: hasNext=%v, want %v", page, paginated.HasNext, wantHasNext)
		}
		itemsBytes, _ := json.Marshal(paginated.Data)
		var items []Report
		if err := json.Unmarshal(itemsBytes, &items); err != nil {
			t.Fatalf("items decode: %v", err)
		}
		for _, item := range items {
			key := item.Namespace + "/" + item.Name
			seen[key]++
			if seen[key] > 1 {
				t.Fatalf("duplicate item across pages: %s", key)
			}
			ordered = append(ordered, key)
		}
		if !paginated.HasNext {
			break
		}
		page++
		if page > 10 {
			t.Fatal("pagination did not terminate within 10 pages")
		}
	}
	if total != 45 {
		t.Fatalf("total = %d, want 45", total)
	}
	if len(seen) != 45 {
		t.Fatalf("walked %d unique items, want 45 (some pages lost items)", len(seen))
	}
	// withVulnerabilities: i%4 > 0 for i in 0..44 -> 33 items (i not divisible by 4)
	if withVuln != 33 {
		t.Fatalf("withVulnerabilities = %d, want 33", withVuln)
	}
	// Order must follow SortKey: namespace ascending, then name ascending.
	sorted := append([]string(nil), ordered...)
	sortStrings(sorted)
	for i := range ordered {
		if ordered[i] != sorted[i] {
			t.Fatalf("order mismatch at %d: %s vs sorted %s", i, ordered[i], sorted[i])
		}
	}
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func TestGetReportsV1_OutOfRangePageReturnsEmptyDataWithTotal(t *testing.T) {
	reports := make([]Report, 5)
	for i := range reports {
		name := fmt.Sprintf("r%d", i)
		reports[i] = Report{Type: "vulns", Cluster: "c", Namespace: "default", Name: name, UpdatedAt: time.Now()}
	}
	h := newReportsHandler(map[string][]Report{"vulns-oob": reports})

	rec := httptest.NewRecorder()
	h.GetReportsV1(rec, httptest.NewRequest(http.MethodGet, "/api/v1/reports?type=vulns-oob&page=99&pageSize=10", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	resp := decodeResponse(t, rec)
	dataBytes, _ := json.Marshal(resp.Data)
	var paginated PaginatedResponse
	if err := json.Unmarshal(dataBytes, &paginated); err != nil {
		t.Fatal(err)
	}
	if paginated.Total != 5 || paginated.HasNext {
		t.Fatalf("out-of-range page: total=%d hasNext=%v, want total=5 false",
			paginated.Total, paginated.HasNext)
	}
	itemsBytes, _ := json.Marshal(paginated.Data)
	var items []Report
	if err := json.Unmarshal(itemsBytes, &items); err != nil || len(items) != 0 {
		t.Fatalf("out-of-range page should return empty items, got %s (err=%v)", itemsBytes, err)
	}
}

func TestGetReportsV1_Filters(t *testing.T) {
	vulned := Report{
		Type: "vulns", Cluster: "prod", Namespace: "payments", Name: "gateway",
		Data: map[string]interface{}{"report": map[string]interface{}{"summary": map[string]interface{}{
			"criticalCount": float64(2),
		}}},
		UpdatedAt: time.Now(),
	}
	clean := Report{
		Type: "vulns", Cluster: "prod", Namespace: "default", Name: "clean-app",
		Data: map[string]interface{}{"report": map[string]interface{}{"summary": map[string]interface{}{
			"criticalCount": float64(0),
		}}},
		UpdatedAt: time.Now(),
	}
	otherCluster := Report{
		Type: "vulns", Cluster: "dev", Namespace: "payments", Name: "gateway-dev",
		Data: map[string]interface{}{"report": map[string]interface{}{"summary": map[string]interface{}{
			"highCount": float64(1),
		}}},
		UpdatedAt: time.Now(),
	}
	h := newReportsHandler(map[string][]Report{"vulns-filters": {vulned, clean, otherCluster}})

	tests := []struct {
		name      string
		query     string
		wantTotal int
	}{
		{"no filter", "", 3},
		{"cluster filter", "&cluster=prod", 2},
		{"namespace filter", "&namespace=payments", 2},
		{"multi namespace filter", "&namespace=payments,default", 3},
		{"namespace with spaces", "&namespace=payments,%20default", 3},
		{"unknown namespace", "&namespace=nope", 0},
		{"only vulnerable", "&onlyVulnerable=true", 2},
		{"only vulnerable + cluster", "&onlyVulnerable=true&cluster=dev", 1},
		{"search by report name", "&search=gateway", 2},
		{"search no match", "&search=does-not-exist", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.GetReportsV1(rec, httptest.NewRequest(http.MethodGet, "/api/v1/reports?type=vulns-filters"+tc.query, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
			}
			resp := decodeResponse(t, rec)
			dataBytes, _ := json.Marshal(resp.Data)
			var paginated PaginatedResponse
			if err := json.Unmarshal(dataBytes, &paginated); err != nil {
				t.Fatal(err)
			}
			if paginated.Total != tc.wantTotal {
				t.Fatalf("%s: total = %d, want %d", tc.name, paginated.Total, tc.wantTotal)
			}
		})
	}
}

func TestGetReportsByTypeV1_IncompleteDataIs503(t *testing.T) {
	cache := &stubCacheService{reports: map[string][]Report{"vulns": {
		{Name: "r1", Type: "vulns", Cluster: "c", Namespace: "ns", UpdatedAt: time.Now()},
	}}}
	h := NewHandler(nil, cache, nil, incompleteQueryService{}, nil, nil, nil)

	rec := httptest.NewRecorder()
	h.GetReportsByTypeV1(rec, httptest.NewRequest(http.MethodGet, "/api/type/vulns", nil), "vulns")

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	resp := decodeResponse(t, rec)
	if resp.Error == nil || resp.Error.Type != string(ErrDataIncomplete) {
		t.Fatalf("error.type = %+v, want %s", resp.Error, ErrDataIncomplete)
	}
}

type incompleteQueryService struct{}

func (incompleteQueryService) ListReports(ReportQuery) QueryResult {
	return QueryResult{Incomplete: true, Items: []Report{}}
}

func TestGetReportsV1_EnvelopeShape(t *testing.T) {
	h := newReportsHandler(map[string][]Report{})
	rec := httptest.NewRecorder()
	h.GetReportsV1(rec, httptest.NewRequest(http.MethodGet, "/api/v1/reports?type=none", nil))

	var raw map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"code", "message"} {
		if _, ok := raw[key]; !ok {
			t.Fatalf("success envelope missing %q: %v", key, raw)
		}
	}
	if strings.Contains(rec.Header().Get("Content-Type"), "json") == false {
		t.Fatalf("content-type = %q", rec.Header().Get("Content-Type"))
	}
}
