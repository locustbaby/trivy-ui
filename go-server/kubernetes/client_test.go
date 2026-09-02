package kubernetes

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"

	"trivy-ui/config"
)

func TestClientGetsClusterScopedDetailsWithoutNamespace(t *testing.T) {
	object := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "aquasecurity.github.io/v1alpha1",
		"kind":       "ClusterVulnerabilityReport",
		"metadata": map[string]interface{}{
			"name": "cluster-report",
		},
	}}
	c := &Client{dynamic: fake.NewSimpleDynamicClient(runtime.NewScheme(), object)}
	report, err := c.GetReportDetails(context.Background(), config.ReportKind{
		Name:       "clustervulnerabilityreports",
		APIVersion: "aquasecurity.github.io/v1alpha1",
		Namespaced: false,
	}, "", "cluster-report")
	if err != nil {
		t.Fatal(err)
	}
	if report.Name != "cluster-report" || report.Namespace != "" {
		t.Fatalf("unexpected cluster-scoped report: %+v", report)
	}
}

func TestClientListsClusterScopedReportsWithoutNamespace(t *testing.T) {
	object := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "aquasecurity.github.io/v1alpha1",
		"kind":       "ClusterVulnerabilityReport",
		"metadata": map[string]interface{}{
			"name": "cluster-report",
		},
	}}
	c := &Client{dynamic: fake.NewSimpleDynamicClient(runtime.NewScheme(), object)}
	items, err := c.ListReports(context.Background(), config.ReportKind{
		Name:       "clustervulnerabilityreports",
		APIVersion: "aquasecurity.github.io/v1alpha1",
		Namespaced: false,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].GetName() != "cluster-report" {
		t.Fatalf("unexpected cluster-scoped reports: %#v", items)
	}
}

func TestClientRejectsNamespaceForClusterScopedDetails(t *testing.T) {
	c := &Client{}
	_, err := c.GetReportDetails(context.Background(), config.ReportKind{
		Name:       "clustervulnerabilityreports",
		APIVersion: "aquasecurity.github.io/v1alpha1",
		Namespaced: false,
	}, "team-a", "cluster-report")
	if err == nil {
		t.Fatal("expected namespace on a cluster-scoped detail request to be rejected")
	}
}
