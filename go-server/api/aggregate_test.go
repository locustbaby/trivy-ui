package api

import (
	"testing"

	"trivy-ui/kubernetes"
)

func testReport(cluster, namespace, reportType, name, rsName string, summary map[string]interface{}, derived map[string]interface{}) Report {
	data := map[string]interface{}{
		"report": map[string]interface{}{"summary": summary},
		"metadata": map[string]interface{}{"labels": map[string]interface{}{
			"trivy-operator.resource.kind":      "ReplicaSet",
			"trivy-operator.resource.name":      rsName,
			"trivy-operator.resource.namespace": namespace,
		}},
	}
	if derived != nil {
		data["derived"] = derived
	}
	return Report{Cluster: cluster, Namespace: namespace, Type: reportType, Name: name, Data: data}
}

func counts(critical, high, medium, low, unknown float64) map[string]interface{} {
	return map[string]interface{}{"criticalCount": critical, "highCount": high, "mediumCount": medium, "lowCount": low, "unknownCount": unknown}
}

func fixable(critical, high int) map[string]interface{} {
	return map[string]interface{}{"version": 1, "fixable": map[string]interface{}{"critical": critical, "high": high}}
}

// Fixture: a Deployment with two containers, a retired ReplicaSet of the same
// Deployment, a second namespace, and other report families.
func overviewFixture() ([]Report, workloadResolverFunc) {
	reports := []Report{
		testReport("nuc", "default", "vulnerabilityreports", "replicaset-immich-774c8dc468-server", "immich-774c8dc468", counts(3, 10, 4, 2, 50), fixable(2, 8)),
		testReport("nuc", "default", "vulnerabilityreports", "replicaset-immich-774c8dc468-ml", "immich-774c8dc468", counts(1, 5, 0, 0, 7), fixable(1, 1)),
		testReport("nuc", "default", "vulnerabilityreports", "replicaset-immich-6b8d4f9c7-server", "immich-6b8d4f9c7", counts(9, 9, 9, 9, 9), fixable(9, 9)),
		testReport("nuc", "media", "vulnerabilityreports", "replicaset-jellyfin-84659bbfd-jellyfin", "jellyfin-84659bbfd", counts(0, 13, 1, 0, 0), fixable(0, 4)),
		testReport("nuc", "", "clusterrbacassessmentreports", "clusterrole-admin", "", counts(27, 14, 0, 0, 0), nil),
		testReport("nuc", "default", "configauditreports", "replicaset-immich-774c8dc468", "immich-774c8dc468", counts(0, 2, 5, 0, 0), nil),
		testReport("nuc", "default", "exposedsecretreports", "replicaset-immich-774c8dc468-server", "immich-774c8dc468", counts(0, 0, 0, 0, 0), nil),
		{Cluster: "nuc", Type: "clustercompliancereports", Name: "nsa", Data: map[string]interface{}{"derived": map[string]interface{}{"version": 1, "compliance": map[string]interface{}{"pass": 40, "fail": 7}}}},
	}
	resolve := func(report Report) kubernetes.Workload {
		workload := (*kubernetes.WorkloadResolver)(nil).Resolve(reportLabels(report), report.Name)
		if report.Name == "replicaset-immich-6b8d4f9c7-server" {
			workload.Retired = true
		}
		return workload
	}
	return reports, resolve
}

func TestAggregateOverviewSeparatesFamilies(t *testing.T) {
	reports, resolve := overviewFixture()
	overview := aggregateOverview(reports, nil, resolve)

	vulns := overview.Families.Vulnerabilities
	if vulns.Reports != 3 || vulns.Critical != 4 || vulns.High != 28 || vulns.Unknown != 57 || vulns.FixableCritical != 3 || vulns.FixableHigh != 13 {
		t.Fatalf("vulnerabilities = %+v", vulns)
	}
	if rbac := overview.Families.RBAC; rbac.Critical != 27 || rbac.High != 14 || rbac.Reports != 1 {
		t.Fatalf("rbac = %+v", rbac)
	}
	if misconfig := overview.Families.Misconfigurations; misconfig.High != 2 || misconfig.Medium != 5 {
		t.Fatalf("misconfigurations = %+v", misconfig)
	}
	if secrets := overview.Families.Secrets; secrets.Reports != 1 || secrets.WithFindings != 0 {
		t.Fatalf("secrets = %+v", secrets)
	}
	if compliance := overview.Families.Compliance; compliance.Pass != 40 || compliance.Fail != 7 {
		t.Fatalf("compliance = %+v", compliance)
	}
	if overview.RetiredReports != 1 || overview.TotalReports != 7 {
		t.Fatalf("retired=%d total=%d", overview.RetiredReports, overview.TotalReports)
	}
	// Legacy totals still add up every type (minus retired), now with unknown.
	if overview.SeverityTotals.Critical != 31 || overview.SeverityTotals.Unknown != 57 {
		t.Fatalf("severity totals = %+v", overview.SeverityTotals)
	}
	if b := overview.ScanTypesBreakdown["vulnerabilityreports"]; b.Scanned != 3 || b.WithFindings != 3 || b.Failed != 3 {
		t.Fatalf("breakdown = %+v", b)
	}
}

func TestAggregateOverviewGroupsWorkloads(t *testing.T) {
	reports, resolve := overviewFixture()
	overview := aggregateOverview(reports, nil, resolve)

	if len(overview.TopVulnerableWorkloads) != 2 {
		t.Fatalf("top workloads = %+v", overview.TopVulnerableWorkloads)
	}
	top := overview.TopVulnerableWorkloads[0]
	if top.Name != "immich" || top.Kind != "Deployment" || top.Critical != 4 || top.High != 15 || top.FixableCritical != 3 || len(top.Reports) != 2 {
		t.Fatalf("immich should combine both containers and skip the retired ReplicaSet: %+v", top)
	}
	for _, workload := range overview.TopVulnerableWorkloads {
		if workload.Type != "vulnerabilityreports" {
			t.Fatalf("top workloads must only contain vulnerability reports: %+v", workload)
		}
	}
	if len(overview.VulnerableNamespaces) != 2 || overview.VulnerableNamespaces[0].Name != "default" {
		t.Fatalf("namespaces = %+v", overview.VulnerableNamespaces)
	}
	for _, namespace := range overview.VulnerableNamespaces {
		if namespace.Name == "" {
			t.Fatal("cluster-scoped RBAC findings must not appear as an unnamed namespace")
		}
	}
}

func TestVulnerabilityTrendRecords(t *testing.T) {
	reports, resolve := overviewFixture()
	scopes := map[string]map[string]struct{}{"nuc": {"_": {}, "default": {}, "empty": {}}}
	records := vulnerabilityTrendRecords(reports, resolve, scopes)
	byScope := map[string]TrendRecord{}
	for _, record := range records {
		if record.Kind != TrendKindVulnerabilities {
			t.Fatalf("kind = %q", record.Kind)
		}
		byScope[record.Cluster+"/"+record.Namespace] = record
	}
	if global := byScope["/"]; global.Critical != 4 || global.High != 28 || global.Unknown != 57 || global.FixableHigh != 13 {
		t.Fatalf("global = %+v", global)
	}
	if cluster := byScope["nuc/"]; cluster.Critical != 4 {
		t.Fatalf("cluster = %+v", cluster)
	}
	if media := byScope["nuc/media"]; media.High != 13 {
		t.Fatalf("media = %+v", media)
	}
	if empty, ok := byScope["nuc/empty"]; !ok || empty.Critical != 0 {
		t.Fatalf("known empty namespaces get a zero record: %+v %v", empty, ok)
	}
	if clusterScoped := byScope["nuc/_"]; clusterScoped.Critical != 0 {
		t.Fatalf("RBAC findings must not count as vulnerabilities: %+v", clusterScoped)
	}
}

func TestSetReportRefreshesSummaryWithoutDerivedCounts(t *testing.T) {
	if err := InitCache(); err != nil {
		t.Skipf("cannot init cache: %v", err)
	}
	updater := NewCacheUpdater(nil)
	key := reportKey("derived-test", "default", "vulnerabilityreports", "r1")
	t.Cleanup(func() { GetCache().Delete(key) })
	old := map[string]interface{}{"report": map[string]interface{}{"summary": counts(1, 0, 0, 0, 0)}}
	updater.SetReport("derived-test", "default", "vulnerabilityreports", "r1", &kubernetes.Report{ResourceVersion: "7", Data: old})
	current := map[string]interface{}{"report": map[string]interface{}{"summary": counts(1, 0, 0, 0, 0)}, "derived": fixable(1, 0)}
	updater.SetReport("derived-test", "default", "vulnerabilityreports", "r1", &kubernetes.Report{ResourceVersion: "7", Data: current})
	value, _ := GetCache().Get(key)
	report, _ := decodeReportValue(value)
	if derivedVersion(report) != kubernetes.DerivedVersion {
		t.Fatal("a cached summary without derived counts must be replaced even when the resourceVersion is unchanged")
	}
}
