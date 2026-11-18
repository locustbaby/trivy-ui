package kubernetes

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestDeriveSummaryCountsFixableAndUniquePerSeverity(t *testing.T) {
	obj := map[string]interface{}{"report": map[string]interface{}{"vulnerabilities": []interface{}{
		map[string]interface{}{"vulnerabilityID": "CVE-1", "severity": "CRITICAL", "fixedVersion": "1.2"},
		map[string]interface{}{"vulnerabilityID": "CVE-1", "severity": "CRITICAL", "fixedVersion": ""},
		map[string]interface{}{"vulnerabilityID": "CVE-2", "severity": "HIGH", "fixedVersion": " "},
		map[string]interface{}{"vulnerabilityID": "CVE-3", "severity": "UNKNOWN", "fixedVersion": "2.0"},
		map[string]interface{}{"vulnerabilityID": "CVE-4", "fixedVersion": "3.0"},
		"not-a-map",
	}}}
	derived := deriveSummary(obj)
	fixable := derived["fixable"].(map[string]interface{})
	unique := derived["unique"].(map[string]interface{})
	if fixable["critical"] != 1 || fixable["high"] != 0 || fixable["unknown"] != 2 {
		t.Fatalf("fixable = %v", fixable)
	}
	if unique["critical"] != 1 || unique["high"] != 1 || unique["unknown"] != 2 {
		t.Fatalf("unique = %v", unique)
	}
	if derived["version"] != DerivedVersion {
		t.Fatalf("version = %v", derived["version"])
	}
}

func TestStripLargeFieldsKeepsDerivedAndSlimsCompliance(t *testing.T) {
	vuln := &unstructured.Unstructured{Object: map[string]interface{}{
		"report": map[string]interface{}{
			"summary":         map[string]interface{}{"criticalCount": float64(1)},
			"vulnerabilities": []interface{}{map[string]interface{}{"vulnerabilityID": "CVE-1", "severity": "CRITICAL", "fixedVersion": "1"}},
		},
	}}
	out, _ := stripLargeFields(vuln)
	object := out.(*unstructured.Unstructured).Object
	if _, kept := object["report"].(map[string]interface{})["vulnerabilities"]; kept {
		t.Fatal("vulnerabilities must be stripped")
	}
	if object["derived"].(map[string]interface{})["fixable"].(map[string]interface{})["critical"] != 1 {
		t.Fatalf("derived counts missing: %v", object["derived"])
	}

	compliance := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{"compliance": map[string]interface{}{"controls": []interface{}{"large"}}},
		"status": map[string]interface{}{
			"summary":         map[string]interface{}{"passCount": float64(40), "failCount": float64(7)},
			"detailReport":    map[string]interface{}{"results": []interface{}{"large"}},
			"updateTimestamp": "2026-11-07T00:00:00Z",
		},
	}}
	out, _ = stripLargeFields(compliance)
	object = out.(*unstructured.Unstructured).Object
	if _, kept := object["spec"]; kept {
		t.Fatal("compliance spec must be stripped")
	}
	if _, kept := object["status"].(map[string]interface{})["detailReport"]; kept {
		t.Fatal("compliance detailReport must be stripped")
	}
	derived := object["derived"].(map[string]interface{})["compliance"].(map[string]interface{})
	if derived["pass"] != 40 || derived["fail"] != 7 {
		t.Fatalf("compliance counts = %v", derived)
	}
}
