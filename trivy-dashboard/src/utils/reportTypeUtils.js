// Report type utilities

// Map of report types to their display names
export const REPORT_TYPE_DISPLAY_NAMES = {
  'vulnerabilityreports': 'Vulnerability Reports',
  'configauditreports': 'Config Audit Reports',
  'exposedsecretreports': 'Exposed Secret Reports',
  'sbomreports': 'SBOM Reports',
  'infraassessmentreports': 'Infra Assessment Reports',
  'rbacassessmentreports': 'RBAC Assessment Reports',
  'clustervulnerabilityreports': 'Cluster Vulnerability Reports',
  'clusterconfigauditreports': 'Cluster Config Audit Reports',
  'clustersbomreports': 'Cluster SBOM Reports',
  'clusterinfraassessmentreports': 'Cluster Infra Assessment Reports',
  'clusterrbacassessmentreports': 'Cluster RBAC Assessment Reports',
  'clustercompliancereports': 'Cluster Compliance Reports'
};

// Check if a report type is a vulnerability report
export function isVulnerabilityReport(reportType) {
  return reportType === 'vulnerabilityreports' || reportType === 'clustervulnerabilityreports';
}

// Check if a report type is a config audit report
export function isConfigAuditReport(reportType) {
  return reportType === 'configauditreports' || reportType === 'clusterconfigauditreports';
}

// Check if a report type is an exposed secret report
export function isExposedSecretReport(reportType) {
  return reportType === 'exposedsecretreports';
}

// Check if a report type is a SBOM report
export function isSbomReport(reportType) {
  return reportType === 'sbomreports' || reportType === 'clustersbomreports';
}

// Check if a report type is an infra assessment report
export function isInfraAssessmentReport(reportType) {
  return reportType === 'infraassessmentreports' || reportType === 'clusterinfraassessmentreports';
}

// Check if a report type is a RBAC assessment report
export function isRbacAssessmentReport(reportType) {
  return reportType === 'rbacassessmentreports' || reportType === 'clusterrbacassessmentreports';
}

// Check if a report type is a compliance report
export function isComplianceReport(reportType) {
  return reportType === 'clustercompliancereports';
}

// Check if a report type is a cluster-level report
export function isClusterLevelReport(reportType) {
  return reportType.startsWith('cluster');
}

// Get the report level (Cluster or Namespace)
export function getReportLevel(reportType) {
  return isClusterLevelReport(reportType) ? 'Cluster' : 'Namespace';
}

// Get severity count from a report based on report type
export function getSeverityCount(report, severity, reportType) {
  // For vulnerability reports
  if (isVulnerabilityReport(reportType)) {
    if (report?.report?.summary) {
      const summary = report.report.summary;
      switch (severity) {
        case 'CRITICAL': return summary.criticalCount || 0;
        case 'HIGH': return summary.highCount || 0;
        case 'MEDIUM': return summary.mediumCount || 0;
        case 'LOW': return summary.lowCount || 0;
        case 'UNKNOWN': return summary.unknownCount || 0;
        default: return 0;
      }
    }

    if (Array.isArray(report?.report?.vulnerabilities)) {
      return report.report.vulnerabilities.filter(v => v.severity === severity).length;
    }

    if (report?.data?.report?.summary) {
      const summary = report.data.report.summary;
      switch (severity) {
        case 'CRITICAL': return summary.criticalCount || 0;
        case 'HIGH': return summary.highCount || 0;
        case 'MEDIUM': return summary.mediumCount || 0;
        case 'LOW': return summary.lowCount || 0;
        case 'UNKNOWN': return summary.unknownCount || 0;
        default: return 0;
      }
    }

    if (Array.isArray(report?.data?.report?.vulnerabilities)) {
      return report.data.report.vulnerabilities.filter(v => v.severity === severity).length;
    }
  }

  // For config audit reports
  if (isConfigAuditReport(reportType)) {
    if (report?.report?.summary) {
      const summary = report.report.summary;
      switch (severity) {
        case 'CRITICAL': return summary.criticalCount || 0;
        case 'HIGH': return summary.highCount || 0;
        case 'MEDIUM': return summary.mediumCount || 0;
        case 'LOW': return summary.lowCount || 0;
        case 'UNKNOWN': return summary.unknownCount || 0;
        default: return 0;
      }
    }

    if (Array.isArray(report?.report?.checks)) {
      return report.report.checks.filter(c => c.severity === severity).length;
    }

    if (report?.data?.report?.summary) {
      const summary = report.data.report.summary;
      switch (severity) {
        case 'CRITICAL': return summary.criticalCount || 0;
        case 'HIGH': return summary.highCount || 0;
        case 'MEDIUM': return summary.mediumCount || 0;
        case 'LOW': return summary.lowCount || 0;
        case 'UNKNOWN': return summary.unknownCount || 0;
        default: return 0;
      }
    }

    if (Array.isArray(report?.data?.report?.checks)) {
      return report.data.report.checks.filter(c => c.severity === severity).length;
    }
  }

  // For exposed secret reports
  if (isExposedSecretReport(reportType)) {
    if (report?.report?.summary) {
      const summary = report.report.summary;
      switch (severity) {
        case 'CRITICAL': return summary.criticalCount || 0;
        case 'HIGH': return summary.highCount || 0;
        case 'MEDIUM': return summary.mediumCount || 0;
        case 'LOW': return summary.lowCount || 0;
        default: return 0;
      }
    }

    if (Array.isArray(report?.report?.secrets)) {
      return report.report.secrets.filter(s => s.severity === severity).length;
    }

    if (report?.data?.report?.summary) {
      const summary = report.data.report.summary;
      switch (severity) {
        case 'CRITICAL': return summary.criticalCount || 0;
        case 'HIGH': return summary.highCount || 0;
        case 'MEDIUM': return summary.mediumCount || 0;
        case 'LOW': return summary.lowCount || 0;
        default: return 0;
      }
    }

    if (Array.isArray(report?.data?.report?.secrets)) {
      return report.data.report.secrets.filter(s => s.severity === severity).length;
    }
  }

  // For other report types, try to find a summary or count
  if (report?.report?.summary?.[`${severity.toLowerCase()}Count`]) {
    return report.report.summary[`${severity.toLowerCase()}Count`];
  }

  if (report?.data?.report?.summary?.[`${severity.toLowerCase()}Count`]) {
    return report.data.report.summary[`${severity.toLowerCase()}Count`];
  }

  return 0;
}

// Get the appropriate detail items for a report based on its type
export function getReportDetailItems(report, reportType) {
  if (isVulnerabilityReport(reportType)) {
    return report?.report?.vulnerabilities || report?.data?.report?.vulnerabilities || [];
  }

  if (isConfigAuditReport(reportType)) {
    return report?.report?.checks || report?.data?.report?.checks || [];
  }

  if (isExposedSecretReport(reportType)) {
    return report?.report?.secrets || report?.data?.report?.secrets || [];
  }

  if (isSbomReport(reportType)) {
    return report?.report?.components || report?.data?.report?.components || [];
  }

  // Default case - try to find any array of items in the report
  const possibleArrays = [
    report?.report?.items,
    report?.data?.report?.items,
    report?.report?.results,
    report?.data?.report?.results,
    report?.report?.findings,
    report?.data?.report?.findings
  ];

  for (const arr of possibleArrays) {
    if (Array.isArray(arr) && arr.length > 0) {
      return arr;
    }
  }

  return [];
}

// Get the appropriate columns for a report detail table based on report type
export function getReportDetailColumns(reportType) {
  if (isVulnerabilityReport(reportType)) {
    return [
      {
        title: 'ID',
        key: 'vulnerabilityID',
        sorter: 'default',
        render: (row) => {
          const link = row.primaryLink || `https://avd.aquasec.com/nvd/${row.vulnerabilityID?.toLowerCase()}`;
          return { type: 'link', text: row.vulnerabilityID, link };
        }
      },
      {
        title: 'Severity',
        key: 'severity',
        sorter: (a, b) => {
          const severityOrder = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, UNKNOWN: 1 };
          return severityOrder[a.severity] - severityOrder[b.severity];
        },
        render: (row) => {
          return { type: 'tag', text: row.severity };
        }
      },
      {
        title: 'Resource',
        key: 'resource',
        sorter: 'default'
      },
      {
        title: 'Installed Version',
        key: 'installedVersion'
      },
      {
        title: 'Fixed Version',
        key: 'fixedVersion'
      },
      {
        title: 'Title',
        key: 'title',
        ellipsis: true
      }
    ];
  }

  if (isConfigAuditReport(reportType)) {
    return [
      {
        title: 'ID',
        key: 'id',
        sorter: 'default'
      },
      {
        title: 'Severity',
        key: 'severity',
        sorter: (a, b) => {
          const severityOrder = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, UNKNOWN: 1 };
          return severityOrder[a.severity] - severityOrder[b.severity];
        },
        render: (row) => {
          return { type: 'tag', text: row.severity };
        }
      },
      {
        title: 'Category',
        key: 'category'
      },
      {
        title: 'Title',
        key: 'title',
        ellipsis: true
      },
      {
        title: 'Description',
        key: 'description',
        ellipsis: true
      }
    ];
  }

  if (isExposedSecretReport(reportType)) {
    return [
      {
        title: 'Rule ID',
        key: 'ruleID',
        sorter: 'default'
      },
      {
        title: 'Severity',
        key: 'severity',
        sorter: (a, b) => {
          const severityOrder = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, UNKNOWN: 1 };
          return severityOrder[a.severity] - severityOrder[b.severity];
        },
        render: (row) => {
          return { type: 'tag', text: row.severity };
        }
      },
      {
        title: 'Category',
        key: 'category'
      },
      {
        title: 'Target',
        key: 'target'
      },
      {
        title: 'Title',
        key: 'title',
        ellipsis: true
      }
    ];
  }

  if (isSbomReport(reportType)) {
    return [
      {
        title: 'Name',
        key: 'name',
        sorter: 'default'
      },
      {
        title: 'Version',
        key: 'version'
      },
      {
        title: 'Type',
        key: 'type'
      },
      {
        title: 'PURL',
        key: 'purl',
        ellipsis: true
      },
      {
        title: 'Licenses',
        key: 'licenses',
        render: (row) => {
          if (Array.isArray(row.licenses)) {
            return row.licenses.map(l => l.name || l).join(', ');
          }
          return row.licenses || '';
        }
      }
    ];
  }

  // Default columns for any report type
  return [
    {
      title: 'ID',
      key: 'id',
      sorter: 'default'
    },
    {
      title: 'Severity',
      key: 'severity',
      sorter: (a, b) => {
        const severityOrder = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, UNKNOWN: 1 };
        return severityOrder[a.severity] - severityOrder[b.severity];
      },
      render: (row) => {
        return { type: 'tag', text: row.severity };
      }
    },
    {
      title: 'Title',
      key: 'title',
      ellipsis: true
    },
    {
      title: 'Description',
      key: 'description',
      ellipsis: true
    }
  ];
}

// Get the title for the report detail modal based on report type
export function getReportDetailTitle(reportType) {
  if (isVulnerabilityReport(reportType)) {
    return 'Vulnerability Report Details';
  }
  if (isConfigAuditReport(reportType)) {
    return 'Config Audit Report Details';
  }
  if (isExposedSecretReport(reportType)) {
    return 'Exposed Secret Report Details';
  }
  if (isSbomReport(reportType)) {
    return 'SBOM Report Details';
  }
  if (isInfraAssessmentReport(reportType)) {
    return 'Infrastructure Assessment Report Details';
  }
  if (isRbacAssessmentReport(reportType)) {
    return 'RBAC Assessment Report Details';
  }
  if (isComplianceReport(reportType)) {
    return 'Compliance Report Details';
  }

  return 'Report Details';
}

// Get the summary fields for a report based on its type
export function getReportSummaryFields(report, reportType) {
  const commonFields = [
    { label: 'Name', value: report.metadata?.name },
    { label: 'Namespace', value: report.metadata?.namespace },
    { label: 'Created', value: report.metadata?.creationTimestamp, type: 'date' }
  ];

  if (isVulnerabilityReport(reportType)) {
    return [
      ...commonFields,
      {
        label: 'Image',
        value: report.report?.artifact || report.data?.report?.artifact,
        type: 'image'
      },
      {
        label: 'OS',
        value: report.report?.os || report.data?.report?.os,
        type: 'os'
      },
      {
        label: 'Scanner',
        value: report.report?.scanner || report.data?.report?.scanner,
        type: 'scanner'
      }
    ];
  }

  if (isConfigAuditReport(reportType)) {
    return [
      ...commonFields,
      {
        label: 'Scanner',
        value: report.report?.scanner || report.data?.report?.scanner,
        type: 'scanner'
      },
      {
        label: 'Resource',
        value: getResourceInfo(report, reportType),
        type: 'text'
      }
    ];
  }

  if (isExposedSecretReport(reportType)) {
    return [
      ...commonFields,
      {
        label: 'Scanner',
        value: report.report?.scanner || report.data?.report?.scanner,
        type: 'scanner'
      },
      {
        label: 'Resource',
        value: getResourceInfo(report, reportType),
        type: 'text'
      }
    ];
  }

  // Default fields for any report type
  return commonFields;
}

// Get resource information from a report
export function getResourceInfo(report, reportType) {
  // Try to get resource kind and name from different possible locations
  let kind = report.metadata?.labels?.['trivy-operator.resource.kind'] ||
             report.data?.metadata?.labels?.['trivy-operator.resource.kind'] ||
             report.metadata?.labels?.['resource.kind'] ||
             report.data?.metadata?.labels?.['resource.kind'];

  let name = report.metadata?.labels?.['trivy-operator.resource.name'] ||
             report.data?.metadata?.labels?.['trivy-operator.resource.name'] ||
             report.metadata?.labels?.['resource.name'] ||
             report.data?.metadata?.labels?.['resource.name'];

  // If still not found, try to extract from the report name
  if (!kind || !name) {
    const reportName = report.metadata?.name || '';
    const parts = reportName.split('-');
    if (parts.length >= 3) {
      // The format is often something like: 'vulnerabilityreport-deployment-nginx'
      kind = parts[1] || '';
      name = parts.slice(2).join('-') || '';

      // Capitalize the first letter of kind
      if (kind) {
        kind = kind.charAt(0).toUpperCase() + kind.slice(1);
      }
    }
  }

  return kind && name ? `${kind}/${name}` : 'N/A';
}
