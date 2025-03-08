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
    if (severity === 'CRITICAL') return summary.criticalCount || 0
    if (severity === 'HIGH') return summary.highCount || 0
    if (severity === 'MEDIUM') return summary.mediumCount || 0
    if (severity === 'LOW') return summary.lowCount || 0
  }
  
  // Check if vulnerabilities are in report.vulnerabilities array
  if (Array.isArray(row?.report?.vulnerabilities)) {
    return row.report.vulnerabilities.filter(v => v.severity === severity).length
  }
  
  return 0
}