package config

// ReportKind represents the kind of a Trivy report
type ReportKind struct {
	Name       string // API resource name
	ShortName  string // Short name for the resource
	APIVersion string // API version
	Namespaced bool   // Whether the resource is namespaced
	Kind       string // Kubernetes kind
}

// Report types
var (
	// Cluster-wide reports
	ClusterComplianceReport = ReportKind{
		Name:       "clustercompliancereports",
		ShortName:  "compliance",
		APIVersion: "aquasecurity.github.io/v1alpha1",
		Namespaced: false,
		Kind:       "ClusterComplianceReport",
	}

	ClusterConfigAuditReport = ReportKind{
		Name:       "clusterconfigauditreports",
		ShortName:  "clusterconfigaudit",
		APIVersion: "aquasecurity.github.io/v1alpha1",
		Namespaced: false,
		Kind:       "ClusterConfigAuditReport",
	}

	ClusterInfraAssessmentReport = ReportKind{
		Name:       "clusterinfraassessmentreports",
		ShortName:  "clusterinfraassessment",
		APIVersion: "aquasecurity.github.io/v1alpha1",
		Namespaced: false,
		Kind:       "ClusterInfraAssessmentReport",
	}

	ClusterRbacAssessmentReport = ReportKind{
		Name:       "clusterrbacassessmentreports",
		ShortName:  "clusterrbacassessmentreport",
		APIVersion: "aquasecurity.github.io/v1alpha1",
		Namespaced: false,
		Kind:       "ClusterRbacAssessmentReport",
	}

	ClusterSbomReport = ReportKind{
		Name:       "clustersbomreports",
		ShortName:  "clustersbom",
		APIVersion: "aquasecurity.github.io/v1alpha1",
		Namespaced: false,
		Kind:       "ClusterSbomReport",
	}

	ClusterVulnerabilityReport = ReportKind{
		Name:       "clustervulnerabilityreports",
		ShortName:  "clustervuln",
		APIVersion: "aquasecurity.github.io/v1alpha1",
		Namespaced: false,
		Kind:       "ClusterVulnerabilityReport",
	}

	// Namespaced reports
	ConfigAuditReport = ReportKind{
		Name:       "configauditreports",
		ShortName:  "configaudit",
		APIVersion: "aquasecurity.github.io/v1alpha1",
		Namespaced: true,
		Kind:       "ConfigAuditReport",
	}

	ExposedSecretReport = ReportKind{
		Name:       "exposedsecretreports",
		ShortName:  "exposedsecret",
		APIVersion: "aquasecurity.github.io/v1alpha1",
		Namespaced: true,
		Kind:       "ExposedSecretReport",
	}

	InfraAssessmentReport = ReportKind{
		Name:       "infraassessmentreports",
		ShortName:  "infraassessment",
		APIVersion: "aquasecurity.github.io/v1alpha1",
		Namespaced: true,
		Kind:       "InfraAssessmentReport",
	}

	RbacAssessmentReport = ReportKind{
		Name:       "rbacassessmentreports",
		ShortName:  "rbacassessment",
		APIVersion: "aquasecurity.github.io/v1alpha1",
		Namespaced: true,
		Kind:       "RbacAssessmentReport",
	}

	SbomReport = ReportKind{
		Name:       "sbomreports",
		ShortName:  "sbom",
		APIVersion: "aquasecurity.github.io/v1alpha1",
		Namespaced: true,
		Kind:       "SbomReport",
	}

	VulnerabilityReport = ReportKind{
		Name:       "vulnerabilityreports",
		ShortName:  "vuln",
		APIVersion: "aquasecurity.github.io/v1alpha1",
		Namespaced: true,
		Kind:       "VulnerabilityReport",
	}
)

// AllReports contains all report kinds
var AllReports = []ReportKind{
	ClusterComplianceReport,
	ClusterConfigAuditReport,
	ClusterInfraAssessmentReport,
	ClusterRbacAssessmentReport,
	ClusterSbomReport,
	ClusterVulnerabilityReport,
	ConfigAuditReport,
	ExposedSecretReport,
	InfraAssessmentReport,
	RbacAssessmentReport,
	SbomReport,
	VulnerabilityReport,
}

// GetReportByName returns a report kind by its name
func GetReportByName(name string) *ReportKind {
	for _, report := range AllReports {
		if report.Name == name {
			return &report
		}
	}
	return nil
}
