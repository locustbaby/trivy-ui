package kubernetes

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func makeObj(report map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"report": report}
}

func makeSummary(critical, high, medium, low, none float64) map[string]interface{} {
	return map[string]interface{}{
		"criticalCount": critical,
		"highCount":     high,
		"mediumCount":   medium,
		"lowCount":      low,
		"noneCount":     none,
	}
}

func newManager() *ReportInformerManager {
	return &ReportInformerManager{clusterName: "test"}
}

func TestExtractStatus_Critical(t *testing.T) {
	obj := makeObj(map[string]interface{}{"summary": makeSummary(2, 0, 0, 0, 0)})
	m := newManager()
	if got := m.extractStatus(obj); got != "Critical" {
		t.Fatalf("expected Critical got %s", got)
	}
}

func TestExtractStatus_High(t *testing.T) {
	obj := makeObj(map[string]interface{}{"summary": makeSummary(0, 5, 0, 0, 0)})
	m := newManager()
	if got := m.extractStatus(obj); got != "High" {
		t.Fatalf("expected High got %s", got)
	}
}

func TestExtractStatus_Medium(t *testing.T) {
	obj := makeObj(map[string]interface{}{"summary": makeSummary(0, 0, 3, 0, 0)})
	m := newManager()
	if got := m.extractStatus(obj); got != "Medium" {
		t.Fatalf("expected Medium got %s", got)
	}
}

func TestExtractStatus_Low(t *testing.T) {
	obj := makeObj(map[string]interface{}{"summary": makeSummary(0, 0, 0, 1, 0)})
	m := newManager()
	if got := m.extractStatus(obj); got != "Low" {
		t.Fatalf("expected Low got %s", got)
	}
}

func TestExtractStatus_None(t *testing.T) {
	obj := makeObj(map[string]interface{}{"summary": makeSummary(0, 0, 0, 0, 1)})
	m := newManager()
	if got := m.extractStatus(obj); got != "None" {
		t.Fatalf("expected None got %s", got)
	}
}

func TestExtractStatus_Unknown(t *testing.T) {
	m := newManager()
	if got := m.extractStatus(map[string]interface{}{}); got != "Unknown" {
		t.Fatalf("expected Unknown got %s", got)
	}
}

func TestHasVulnerabilities_True(t *testing.T) {
	obj := makeObj(map[string]interface{}{"summary": makeSummary(1, 0, 0, 0, 0)})
	m := newManager()
	if !m.hasVulnerabilities(obj) {
		t.Fatal("expected true")
	}
}

func TestHasVulnerabilities_OnlyHigh(t *testing.T) {
	obj := makeObj(map[string]interface{}{"summary": makeSummary(0, 2, 0, 0, 0)})
	m := newManager()
	if !m.hasVulnerabilities(obj) {
		t.Fatal("expected true")
	}
}

func TestHasVulnerabilities_False(t *testing.T) {
	obj := makeObj(map[string]interface{}{"summary": makeSummary(0, 0, 0, 0, 0)})
	m := newManager()
	if m.hasVulnerabilities(obj) {
		t.Fatal("expected false")
	}
}

func TestHasVulnerabilities_NoReport(t *testing.T) {
	m := newManager()
	if m.hasVulnerabilities(map[string]interface{}{}) {
		t.Fatal("expected false for missing report field")
	}
}

func TestExtractSummaryData_CopiesAllowedKeys(t *testing.T) {
	obj := map[string]interface{}{
		"apiVersion": "aquasecurity.github.io/v1alpha1",
		"kind":       "VulnerabilityReport",
		"metadata": map[string]interface{}{
			"name":      "my-report",
			"namespace": "default",
			"uid":       "abc-123",
		},
		"report": map[string]interface{}{
			"summary":  map[string]interface{}{"criticalCount": float64(2)},
			"artifact": map[string]interface{}{"repository": "nginx"},
			"scanner":  map[string]interface{}{"name": "trivy"},
			"vulnerabilities": []interface{}{
				map[string]interface{}{"vulnerabilityID": "CVE-2021-1234"},
			},
		},
	}
	m := newManager()
	result := m.extractSummaryData(obj)

	if result["apiVersion"] != "aquasecurity.github.io/v1alpha1" {
		t.Error("apiVersion should be copied")
	}
	if result["kind"] != "VulnerabilityReport" {
		t.Error("kind should be copied")
	}

	reportCopy, ok := result["report"].(map[string]interface{})
	if !ok {
		t.Fatal("report should be present")
	}
	if _, hasSummary := reportCopy["summary"]; !hasSummary {
		t.Error("summary should be in report copy")
	}
	if _, hasArtifact := reportCopy["artifact"]; !hasArtifact {
		t.Error("artifact should be in report copy")
	}
	if _, hasVulns := reportCopy["vulnerabilities"]; hasVulns {
		t.Error("vulnerabilities should NOT be copied (large array)")
	}
}

func TestExtractSummaryData_MetadataSubset(t *testing.T) {
	obj := map[string]interface{}{
		"metadata": map[string]interface{}{
			"name":            "r1",
			"namespace":       "ns",
			"uid":             "uid1",
			"resourceVersion": "12345",
			"managedFields":   []interface{}{"big", "data"},
		},
	}
	m := newManager()
	result := m.extractSummaryData(obj)
	meta, ok := result["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("metadata should be present")
	}
	if _, hasRV := meta["resourceVersion"]; hasRV {
		t.Error("resourceVersion should NOT be copied")
	}
	if _, hasMF := meta["managedFields"]; hasMF {
		t.Error("managedFields should NOT be copied")
	}
	if meta["name"] != "r1" {
		t.Error("name should be copied")
	}
}

func TestStripLargeFields_KeepsAllowedKeys(t *testing.T) {
	u := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"report": map[string]interface{}{
				"summary":         map[string]interface{}{"criticalCount": float64(1)},
				"artifact":        map[string]interface{}{"repository": "nginx"},
				"vulnerabilities": []interface{}{"cve1", "cve2"},
				"checks":          []interface{}{"check1"},
			},
		},
	}

	result, err := stripLargeFields(u)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stripped, ok := result.(*unstructured.Unstructured)
	if !ok {
		t.Fatal("result should be *unstructured.Unstructured")
	}
	reportObj, ok := stripped.Object["report"].(map[string]interface{})
	if !ok {
		t.Fatal("report field should exist")
	}
	if _, ok := reportObj["summary"]; !ok {
		t.Error("summary should be kept")
	}
	if _, ok := reportObj["artifact"]; !ok {
		t.Error("artifact should be kept")
	}
	if _, ok := reportObj["vulnerabilities"]; ok {
		t.Error("vulnerabilities should be stripped")
	}
	if _, ok := reportObj["checks"]; ok {
		t.Error("checks should be stripped")
	}
}

func TestStripLargeFields_NonUnstructured(t *testing.T) {
	plain := "not-unstructured"
	result, err := stripLargeFields(plain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != plain {
		t.Fatal("non-unstructured should be returned as-is")
	}
}

func TestParseAPIVersion_Standard(t *testing.T) {
	group, version := parseAPIVersion("aquasecurity.github.io/v1alpha1")
	if group != "aquasecurity.github.io" || version != "v1alpha1" {
		t.Fatalf("got group=%s version=%s", group, version)
	}
}

func TestParseAPIVersion_Empty(t *testing.T) {
	group, version := parseAPIVersion("")
	if group != "aquasecurity.github.io" || version != "v1alpha1" {
		t.Fatalf("empty should return defaults, got group=%s version=%s", group, version)
	}
}

func TestParseAPIVersion_InvalidFormat(t *testing.T) {
	group, version := parseAPIVersion("noslash")
	if group != "aquasecurity.github.io" || version != "v1alpha1" {
		t.Fatalf("no-slash should return defaults, got group=%s version=%s", group, version)
	}
}
