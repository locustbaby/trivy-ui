package config

import (
	"testing"
	"time"
)

func newPopulatedRegistry() *CRDRegistry {
	reg := &CRDRegistry{
		reportsByName: make(map[string]*ReportKind),
		refreshTTL:    5 * time.Minute,
		lastRefresh:   time.Now(),
	}
	reg.reports = []ReportKind{
		{Name: "vulnerabilityreports", Kind: "VulnerabilityReport", Namespaced: true, APIVersion: "aquasecurity.github.io/v1alpha1"},
		{Name: "clustercompliancereports", Kind: "ClusterComplianceReport", Namespaced: false, APIVersion: "aquasecurity.github.io/v1alpha1"},
	}
	for i := range reg.reports {
		reg.reportsByName[reg.reports[i].Name] = &reg.reports[i]
	}
	return reg
}

func TestCRDRegistry_GetAllReports_Empty(t *testing.T) {
	reg := &CRDRegistry{reportsByName: make(map[string]*ReportKind)}
	reports := reg.GetAllReports()
	if len(reports) != 0 {
		t.Fatalf("expected 0 got %d", len(reports))
	}
}

func TestCRDRegistry_GetAllReports_Populated(t *testing.T) {
	reg := newPopulatedRegistry()
	reports := reg.GetAllReports()
	if len(reports) != 2 {
		t.Fatalf("expected 2 got %d", len(reports))
	}
}

func TestCRDRegistry_GetAllReports_ReturnsCopy(t *testing.T) {
	reg := newPopulatedRegistry()
	r1 := reg.GetAllReports()
	r1[0].Name = "modified"
	r2 := reg.GetAllReports()
	if r2[0].Name == "modified" {
		t.Fatal("GetAllReports should return a copy, not reference")
	}
}

func TestCRDRegistry_GetReportByName_Found(t *testing.T) {
	reg := newPopulatedRegistry()
	rk := reg.GetReportByName("vulnerabilityreports")
	if rk == nil {
		t.Fatal("expected non-nil")
	}
	if rk.Kind != "VulnerabilityReport" {
		t.Fatalf("expected VulnerabilityReport got %s", rk.Kind)
	}
}

func TestCRDRegistry_GetReportByName_NotFound(t *testing.T) {
	reg := newPopulatedRegistry()
	rk := reg.GetReportByName("doesnotexist")
	if rk != nil {
		t.Fatal("expected nil for unknown name")
	}
}

func TestCRDRegistry_GetReportByName_ReturnsCopy(t *testing.T) {
	reg := newPopulatedRegistry()
	rk := reg.GetReportByName("vulnerabilityreports")
	rk.Name = "hacked"
	rk2 := reg.GetReportByName("vulnerabilityreports")
	if rk2.Name == "hacked" {
		t.Fatal("GetReportByName should return a copy")
	}
}

func TestCRDRegistry_IsDiscovered_Empty(t *testing.T) {
	reg := &CRDRegistry{reportsByName: make(map[string]*ReportKind)}
	if reg.IsDiscovered() {
		t.Fatal("empty registry should not be discovered")
	}
}

func TestCRDRegistry_IsDiscovered_WithReports(t *testing.T) {
	reg := newPopulatedRegistry()
	if !reg.IsDiscovered() {
		t.Fatal("populated registry should be discovered")
	}
}

func TestCRDRegistry_IsDiscovered_WithLastRefreshOnly(t *testing.T) {
	reg := &CRDRegistry{
		reportsByName: make(map[string]*ReportKind),
		lastRefresh:   time.Now(),
	}
	if !reg.IsDiscovered() {
		t.Fatal("registry with lastRefresh set should be discovered (empty but tried)")
	}
}

func TestCRDRegistry_RefreshIfNeeded_SkipsWhenFresh(t *testing.T) {
	reg := newPopulatedRegistry()
	reg.lastRefresh = time.Now()
	reg.refreshTTL = time.Hour

	err := reg.RefreshIfNeeded(nil)
	if err != nil {
		t.Fatalf("expected no error when skipping refresh, got %v", err)
	}
}

func TestCRDRegistry_GetLastRefreshTime(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	reg := &CRDRegistry{
		reportsByName: make(map[string]*ReportKind),
		lastRefresh:   now,
	}
	got := reg.GetLastRefreshTime().Truncate(time.Second)
	if !got.Equal(now) {
		t.Fatalf("expected %v got %v", now, got)
	}
}

func TestCRDRegistry_Namespaced(t *testing.T) {
	reg := newPopulatedRegistry()
	vuln := reg.GetReportByName("vulnerabilityreports")
	cluster := reg.GetReportByName("clustercompliancereports")

	if !vuln.Namespaced {
		t.Fatal("vulnerabilityreports should be namespaced")
	}
	if cluster.Namespaced {
		t.Fatal("clustercompliancereports should not be namespaced")
	}
}
