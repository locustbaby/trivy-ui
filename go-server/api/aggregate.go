package api

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"trivy-ui/auth"
	"trivy-ui/kubernetes"
)

// Report families: totals are only meaningful within one family. Adding a
// critical CVE to a critical RBAC finding gives a number nobody can act on.
const (
	familyVulnerabilities   = "vulnerabilities"
	familyMisconfigurations = "misconfigurations"
	familyRBAC              = "rbac"
	familySecrets           = "secrets"
	familyCompliance        = "compliance"
)

// TrendKindVulnerabilities marks trend records that count vulnerability
// reports only. Records without a kind come from older versions, which added
// up every report type.
const TrendKindVulnerabilities = "vulnerabilities"

func reportFamily(reportType string) string {
	switch strings.ToLower(reportType) {
	case "vulnerabilityreports", "clustervulnerabilityreports":
		return familyVulnerabilities
	case "configauditreports", "clusterconfigauditreports", "infraassessmentreports", "clusterinfraassessmentreports":
		return familyMisconfigurations
	case "rbacassessmentreports", "clusterrbacassessmentreports":
		return familyRBAC
	case "exposedsecretreports":
		return familySecrets
	case "clustercompliancereports":
		return familyCompliance
	}
	return ""
}

type FamilyTotals struct {
	Reports         int `json:"reports"`
	WithFindings    int `json:"with_findings"`
	Critical        int `json:"critical"`
	High            int `json:"high"`
	Medium          int `json:"medium"`
	Low             int `json:"low"`
	Unknown         int `json:"unknown"`
	FixableCritical int `json:"fixable_critical"`
	FixableHigh     int `json:"fixable_high"`
	FixableMedium   int `json:"fixable_medium"`
	FixableLow      int `json:"fixable_low"`
	FixableUnknown  int `json:"fixable_unknown"`
}

func (t *FamilyTotals) add(counts reportCounts) {
	t.Reports++
	if counts.any() {
		t.WithFindings++
	}
	t.Critical += counts.critical
	t.High += counts.high
	t.Medium += counts.medium
	t.Low += counts.low
	t.Unknown += counts.unknown
	t.FixableCritical += counts.fixableCritical
	t.FixableHigh += counts.fixableHigh
	t.FixableMedium += counts.fixableMedium
	t.FixableLow += counts.fixableLow
	t.FixableUnknown += counts.fixableUnknown
}

type ComplianceTotals struct {
	Reports int `json:"reports"`
	Pass    int `json:"pass"`
	Fail    int `json:"fail"`
}

type FamilyOverview struct {
	Vulnerabilities   FamilyTotals     `json:"vulnerabilities"`
	Misconfigurations FamilyTotals     `json:"misconfigurations"`
	RBAC              FamilyTotals     `json:"rbac"`
	Secrets           FamilyTotals     `json:"secrets"`
	Compliance        ComplianceTotals `json:"compliance"`
}

type reportCounts struct {
	critical, high, medium, low, unknown                                    int
	fixableCritical, fixableHigh, fixableMedium, fixableLow, fixableUnknown int
	compliancePass, complianceFail                                          int
	hasCompliance                                                           bool
}

func (c reportCounts) any() bool {
	return c.critical+c.high+c.medium+c.low+c.unknown > 0
}

func reportData(report Report) map[string]interface{} {
	data, _ := report.Data.(map[string]interface{})
	return data
}

func countReport(report Report) reportCounts {
	var counts reportCounts
	data := reportData(report)
	if data == nil {
		return counts
	}
	var summary map[string]interface{}
	if body, ok := data["report"].(map[string]interface{}); ok {
		summary, _ = body["summary"].(map[string]interface{})
	}
	if summary == nil {
		summary, _ = data["summary"].(map[string]interface{})
	}
	if summary != nil {
		counts.critical = intValue(summary["criticalCount"])
		counts.high = intValue(summary["highCount"])
		counts.medium = intValue(summary["mediumCount"])
		counts.low = intValue(summary["lowCount"])
		counts.unknown = intValue(summary["unknownCount"])
	}
	if derived, ok := data["derived"].(map[string]interface{}); ok {
		if fixable, ok := derived["fixable"].(map[string]interface{}); ok {
			counts.fixableCritical = intValue(fixable["critical"])
			counts.fixableHigh = intValue(fixable["high"])
			counts.fixableMedium = intValue(fixable["medium"])
			counts.fixableLow = intValue(fixable["low"])
			counts.fixableUnknown = intValue(fixable["unknown"])
		}
		if compliance, ok := derived["compliance"].(map[string]interface{}); ok {
			counts.hasCompliance = true
			counts.compliancePass = intValue(compliance["pass"])
			counts.complianceFail = intValue(compliance["fail"])
		}
	}
	return counts
}

func intValue(value interface{}) int {
	switch number := value.(type) {
	case float64:
		return int(number)
	case int:
		return number
	case int64:
		return int(number)
	case uint64:
		return int(number)
	}
	return 0
}

// derivedVersion tells whether a cached summary already carries the derived
// counts of the current version.
func derivedVersion(report Report) int {
	if data := reportData(report); data != nil {
		if derived, ok := data["derived"].(map[string]interface{}); ok {
			return intValue(derived["version"])
		}
	}
	return 0
}

func reportLabels(report Report) map[string]string {
	labels := map[string]string{}
	data := reportData(report)
	if data == nil {
		return labels
	}
	metadata, _ := data["metadata"].(map[string]interface{})
	raw, _ := metadata["labels"].(map[string]interface{})
	for key, value := range raw {
		if text, ok := value.(string); ok {
			labels[key] = text
		}
	}
	if typed, ok := metadata["labels"].(map[string]string); ok {
		for key, value := range typed {
			labels[key] = value
		}
	}
	return labels
}

type workloadResolverFunc func(Report) kubernetes.Workload

// registryWorkloadResolver resolves workloads with the ReplicaSet lookups of
// the clusters in a registry.
func registryWorkloadResolver(registry *ClusterRegistry) workloadResolverFunc {
	return func(report Report) kubernetes.Workload {
		var resolver *kubernetes.WorkloadResolver
		if registry != nil {
			if client := registry.Get(report.Cluster); client != nil && client.Client != nil {
				resolver = client.Client.Workloads()
			}
		}
		return resolver.Resolve(reportLabels(report), report.Name)
	}
}

// workloadGeneration changes whenever a workload lookup may give a different
// answer, so memoized overviews are recomputed.
func workloadGeneration(registry *ClusterRegistry) uint64 {
	if registry == nil {
		return 0
	}
	var total uint64
	for _, client := range registry.All() {
		if client.Client != nil {
			total += client.Client.Workloads().Generation()
		}
	}
	return total
}

func aggregateOverview(reports []Report, include func(Report) bool, resolve workloadResolverFunc) *ClusterOverview {
	overview := &ClusterOverview{
		ScanTypesBreakdown:     make(map[string]TypeBreakdown),
		TopVulnerableWorkloads: []WorkloadSummary{},
		VulnerableClusters:     []ClusterSummary{},
		VulnerableNamespaces:   []NamespaceSummary{},
	}
	workloads := make(map[string]*WorkloadSummary)
	namespaces := make(map[string]*NamespaceSummary)
	clusters := make(map[string]*ClusterSummary)
	staleAfter := currentScanStaleAfter()
	overview.StaleAfterHours = int(staleAfter.Hours())
	staleBefore := time.Now().Add(-staleAfter)

	for _, report := range reports {
		if include != nil && !include(report) {
			continue
		}
		workload := resolve(report)
		if workload.Retired {
			overview.RetiredReports++
			continue
		}
		counts := countReport(report)
		if scanned, ok := reportScannedAt(report); ok && scanned.Before(staleBefore) {
			overview.StaleReports++
		}

		overview.TotalReports++
		overview.SeverityTotals.Critical += counts.critical
		overview.SeverityTotals.High += counts.high
		overview.SeverityTotals.Medium += counts.medium
		overview.SeverityTotals.Low += counts.low
		overview.SeverityTotals.Unknown += counts.unknown
		breakdown := overview.ScanTypesBreakdown[report.Type]
		breakdown.Scanned++
		if counts.any() {
			breakdown.WithFindings++
		}
		breakdown.Failed = breakdown.WithFindings
		breakdown.Critical += counts.critical
		overview.ScanTypesBreakdown[report.Type] = breakdown

		switch reportFamily(report.Type) {
		case familyMisconfigurations:
			overview.Families.Misconfigurations.add(counts)
		case familyRBAC:
			overview.Families.RBAC.add(counts)
		case familySecrets:
			overview.Families.Secrets.add(counts)
		case familyCompliance:
			overview.Families.Compliance.Reports++
			overview.Families.Compliance.Pass += counts.compliancePass
			overview.Families.Compliance.Fail += counts.complianceFail
		case familyVulnerabilities:
			overview.Families.Vulnerabilities.add(counts)
			if counts.critical == 0 && counts.high == 0 {
				continue
			}
			key := fmt.Sprintf("%s\x00%s\x00%s\x00%s", report.Cluster, report.Namespace, workload.Kind, workload.Name)
			entry := workloads[key]
			if entry == nil {
				entry = &WorkloadSummary{Cluster: report.Cluster, Namespace: report.Namespace, Name: workload.Name, Kind: workload.Kind, Type: report.Type}
				workloads[key] = entry
			}
			entry.Critical += counts.critical
			entry.High += counts.high
			entry.FixableCritical += counts.fixableCritical
			entry.FixableHigh += counts.fixableHigh
			entry.Reports = append(entry.Reports, report.Name)

			nsKey := report.Cluster + "\x00" + report.Namespace
			if namespaces[nsKey] == nil {
				namespaces[nsKey] = &NamespaceSummary{Cluster: report.Cluster, Name: report.Namespace}
			}
			namespaces[nsKey].Critical += counts.critical
			namespaces[nsKey].High += counts.high
			namespaces[nsKey].FixableCritical += counts.fixableCritical
			namespaces[nsKey].FixableHigh += counts.fixableHigh

			if clusters[report.Cluster] == nil {
				clusters[report.Cluster] = &ClusterSummary{Name: report.Cluster}
			}
			clusters[report.Cluster].Critical += counts.critical
			clusters[report.Cluster].High += counts.high
			clusters[report.Cluster].FixableCritical += counts.fixableCritical
			clusters[report.Cluster].FixableHigh += counts.fixableHigh
		}
	}

	for _, workload := range workloads {
		sort.Strings(workload.Reports)
		overview.TopVulnerableWorkloads = append(overview.TopVulnerableWorkloads, *workload)
	}
	sort.Slice(overview.TopVulnerableWorkloads, func(i, j int) bool {
		a, b := overview.TopVulnerableWorkloads[i], overview.TopVulnerableWorkloads[j]
		if a.Critical != b.Critical {
			return a.Critical > b.Critical
		}
		if a.High != b.High {
			return a.High > b.High
		}
		return a.Namespace+"/"+a.Name < b.Namespace+"/"+b.Name
	})
	if len(overview.TopVulnerableWorkloads) > 5 {
		overview.TopVulnerableWorkloads = overview.TopVulnerableWorkloads[:5]
	}
	for _, namespace := range namespaces {
		overview.VulnerableNamespaces = append(overview.VulnerableNamespaces, *namespace)
	}
	sort.Slice(overview.VulnerableNamespaces, func(i, j int) bool {
		a, b := overview.VulnerableNamespaces[i], overview.VulnerableNamespaces[j]
		if a.Critical != b.Critical {
			return a.Critical > b.Critical
		}
		if a.High != b.High {
			return a.High > b.High
		}
		return a.Cluster+"/"+a.Name < b.Cluster+"/"+b.Name
	})
	for _, cluster := range clusters {
		overview.VulnerableClusters = append(overview.VulnerableClusters, *cluster)
	}
	sort.Slice(overview.VulnerableClusters, func(i, j int) bool {
		a, b := overview.VulnerableClusters[i], overview.VulnerableClusters[j]
		if a.Critical != b.Critical {
			return a.Critical > b.Critical
		}
		if a.High != b.High {
			return a.High > b.High
		}
		return a.Name < b.Name
	})
	return overview
}

// vulnerabilityTrendRecords counts vulnerability reports (retired ReplicaSets
// excluded) for the whole fleet, every cluster and every namespace scope.
// scopes lists clusters and namespaces that get a record even when empty.
func vulnerabilityTrendRecords(reports []Report, resolve workloadResolverFunc, scopes map[string]map[string]struct{}) []TrendRecord {
	type scope struct{ cluster, namespace string }
	totals := map[scope]*TrendRecord{{}: {}}
	ensure := func(key scope) *TrendRecord {
		if totals[key] == nil {
			totals[key] = &TrendRecord{Cluster: key.cluster, Namespace: key.namespace}
		}
		return totals[key]
	}
	for cluster, namespaces := range scopes {
		ensure(scope{cluster: cluster})
		for namespace := range namespaces {
			ensure(scope{cluster: cluster, namespace: namespace})
		}
	}
	for _, report := range reports {
		if reportFamily(report.Type) != familyVulnerabilities || resolve(report).Retired {
			continue
		}
		namespace := report.Namespace
		if namespace == "" {
			namespace = auth.ClusterScopedNamespace
		}
		counts := countReport(report)
		for _, key := range []scope{{}, {cluster: report.Cluster}, {cluster: report.Cluster, namespace: namespace}} {
			record := ensure(key)
			record.Critical += counts.critical
			record.High += counts.high
			record.Medium += counts.medium
			record.Low += counts.low
			record.Unknown += counts.unknown
			record.FixableCritical += counts.fixableCritical
			record.FixableHigh += counts.fixableHigh
		}
	}
	records := make([]TrendRecord, 0, len(totals))
	for _, record := range totals {
		record.Kind = TrendKindVulnerabilities
		records = append(records, *record)
	}
	return records
}
