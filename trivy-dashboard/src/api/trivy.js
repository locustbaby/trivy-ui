import axios from 'axios'

// Use relative path for API requests when frontend and backend are served from the same domain
// Alternative approach with .env files
const apiBaseUrl = import.meta.env.VITE_API_URL || ''

// Response codes
export const ResponseCode = {
  Success: 0,
  InvalidRequest: 11,
  NotFound: 12,
  AlreadyExists: 13,
  InternalError: 14,
  MethodNotAllowed: 15
}

// Error messages for each code
const ErrorMessages = {
  [ResponseCode.InvalidRequest]: 'Invalid request',
  [ResponseCode.NotFound]: 'Resource not found',
  [ResponseCode.AlreadyExists]: 'Resource already exists',
  [ResponseCode.InternalError]: 'Internal server error',
  [ResponseCode.MethodNotAllowed]: 'Method not allowed'
}

// Helper function to handle API responses
function handleResponse(response) {
  const { code, message, data } = response.data

  if (code === ResponseCode.Success) {
    return response.data
  }

  // If we have a specific error message from the server, use it
  if (message) {
    throw new Error(message)
  }

  // Otherwise use the default error message for the code
  throw new Error(ErrorMessages[code] || 'Unknown error')
}

export async function fetchNamespaces(cluster) {
  if (!cluster) return []
  console.log('API: Fetching namespaces for cluster:', cluster)
  try {
    const response = await axios.get(`${apiBaseUrl}/api/namespaces`, {
      params: { cluster }
    })
    console.log('API: Namespaces response:', response.data)

    // Extract namespace names from the response
    if (Array.isArray(response.data.data)) {
      // Map the namespace objects to just their names
      const namespaceNames = response.data.data.map(ns => ns.name)
      console.log('API: Extracted namespace names:', namespaceNames)
      return namespaceNames
    }

    return []
  } catch (error) {
    console.error('API: Error fetching namespaces:', error)
    throw error
  }
}

export async function fetchReportTypes() {
  const response = await axios.get(`${apiBaseUrl}/api/report-types`)
  return response.data.data || []
}

export async function fetchVulnerabilityReports(cluster, namespace, reportType = 'vulnerabilityreports') {
  if (!namespace || !cluster) return []
  const response = await axios.get(`${apiBaseUrl}/api/reports`, {
    params: {
      type: reportType,
      cluster,
      namespace
    }
  })
  return response.data.data.items || []
}

export async function fetchReportDetails(reportType, cluster, namespace, reportName) {
  if (!namespace || !reportName || !cluster) return null
  const response = await axios.get(`${apiBaseUrl}/api/reports/${reportType}/${cluster}/${namespace}/${reportName}`)
  return response.data
}

export async function fetchClusters() {
  console.log('API: Fetching clusters from', `${apiBaseUrl}/api/clusters`)
  try {
    const response = await axios.get(`${apiBaseUrl}/api/clusters`)
    console.log('API: Clusters response:', response.data)
    return response.data.data || []
  } catch (error) {
    console.error('API: Error fetching clusters:', error)
    throw error
  }
}

export async function addCluster(clusterData) {
  const response = await axios.post(`${apiBaseUrl}/api/clusters`, clusterData)
  return response.data
}

export async function deleteCluster(clusterName) {
  const encodedName = encodeURIComponent(clusterName)
  const response = await axios.delete(`${apiBaseUrl}/api/clusters/${encodedName}`)
  return response.data
}

export async function updateCluster(clusterData) {
  // If only the enable state is changing, don't send to API
  if (clusterData.hasOwnProperty('enable') && Object.keys(clusterData).length === 2 && clusterData.hasOwnProperty('name')) {
    console.log('Enable state change, handling in frontend only:', clusterData)
    return { code: 0, message: 'Success', data: { name: clusterData.name, enable: clusterData.enable } }
  }

  // For other updates, send to API
  console.log('Sending update request:', {
    url: `${apiBaseUrl}/api/clusters/${encodeURIComponent(clusterData.name)}`,
    data: clusterData
  })

  // Use POST for updates since we're keeping the original API
  const response = await axios.post(`${apiBaseUrl}/api/clusters`, clusterData)
  return response.data
}

export async function createCluster(clusterData) {
  try {
    const response = await axios.post('/api/clusters', clusterData)
    return response.data
  } catch (error) {
    if (error.response) {
      // 服务器返回了错误响应
      const { status, data } = error.response
      let errorMessage = 'Failed to create cluster'

      if (data && typeof data === 'string') {
        errorMessage = data
      } else if (data && data.message) {
        errorMessage = data.message
      }

      throw new Error(`${errorMessage} (Status: ${status})`)
    } else if (error.request) {
      // 请求已发送但没有收到响应
      throw new Error('No response from server')
    } else {
      // 请求设置时发生错误
      throw new Error(`Request error: ${error.message}`)
    }
  }
}

export async function fetchReports(reportType, cluster, namespace, refresh = false) {
  console.log('API: Fetching reports for type:', reportType, 'cluster:', cluster, 'namespace:', namespace, 'refresh:', refresh)
  if (!cluster || !namespace) {
    console.warn('API: Missing cluster or namespace, cannot fetch reports')
    return { data: { reports: [] } }
  }

  try {
    const response = await axios.get(`${apiBaseUrl}/api/reports`, {
      params: {
        type: reportType,
        cluster,
        namespace,
        refresh
      }
    })
    console.log('API: Reports response:', response.data)

    // Ensure we return the correct data structure
    if (response.data && response.data.data) {
      return {
        data: {
          reports: Array.isArray(response.data.data.reports) ? response.data.data.reports : [],
          total: response.data.data.total || 0,
          page: response.data.data.page || 1,
          pages: response.data.data.pages || 1
        }
      }
    }
    return { data: { reports: [] } }
  } catch (error) {
    console.error('API: Error fetching reports:', error)
    throw error
  }
}