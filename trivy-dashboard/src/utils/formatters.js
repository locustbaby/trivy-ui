export function formatDate(dateString) {
  if (!dateString) return 'N/A'
  const date = new Date(dateString)
  return date.toLocaleString()
}

export function formatImage(artifact) {
  if (!artifact) return 'N/A'
  let image = ''
  if (artifact.repository) {
    image += artifact.repository
  }
  if (artifact.tag) {
    image += ':' + artifact.tag
  }
  if (artifact.digest) {
    image += ' (' + artifact.digest.substring(0, 12) + ')'
  }
  return image || 'N/A'
}

export function getVulnerabilityCount(row, severity) {
  // Support multiple data structures
  if (row?.report?.summary) {
    const summary = row.report.summary
    switch (severity) {
      case 'CRITICAL': return summary.criticalCount || 0
      case 'HIGH': return summary.highCount || 0
      case 'MEDIUM': return summary.mediumCount || 0
      case 'LOW': return summary.lowCount || 0
      case 'UNKNOWN': return summary.unknownCount || 0
      default: return 0
    }
  }
  
  // Check if vulnerabilities are in report.vulnerabilities array
  if (Array.isArray(row?.report?.vulnerabilities)) {
    return row.report.vulnerabilities.filter(v => v.severity === severity).length
  }
  
  // Check if data is in the nested structure
  if (row?.data?.report?.summary) {
    const summary = row.data.report.summary
    switch (severity) {
      case 'CRITICAL': return summary.criticalCount || 0
      case 'HIGH': return summary.highCount || 0
      case 'MEDIUM': return summary.mediumCount || 0
      case 'LOW': return summary.lowCount || 0
      case 'UNKNOWN': return summary.unknownCount || 0
      default: return 0
    }
  }
  
  // Check if vulnerabilities are in the nested structure
  if (Array.isArray(row?.data?.report?.vulnerabilities)) {
    return row.data.report.vulnerabilities.filter(v => v.severity === severity).length
  }
  
  return 0
}