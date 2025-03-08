import axios from 'axios'

// Use relative path for API requests when frontend and backend are served from the same domain
// Alternative approach with .env files
const apiBaseUrl = import.meta.env.VITE_API_URL || ''

export async function fetchNamespaces() {
  const response = await axios.get(`${apiBaseUrl}/namespaces`)
  return response.data.items || []
}

export async function fetchVulnerabilityReports(namespace) {
  if (!namespace) return []
  const response = await axios.get(`${apiBaseUrl}/vulnerability-reports?namespace=${namespace}`)
  return response.data.items || []
}

export async function fetchReportDetails(namespace, reportName) {
  if (!namespace || !reportName) return null
  const response = await axios.get(`${apiBaseUrl}/report-details?namespace=${namespace}&reportName=${reportName}`)
  return response.data
}