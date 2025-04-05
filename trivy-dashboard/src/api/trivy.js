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
  const response = await axios.get(`${apiBaseUrl}/namespaces?cluster=${cluster}`)
  return response.data.items || []
}

export async function fetchVulnerabilityReports(namespace, cluster) {
  if (!namespace || !cluster) return []
  const response = await axios.get(`${apiBaseUrl}/vulnerability-reports?namespace=${namespace}&cluster=${cluster}`)
  return response.data.items || []
}

export async function fetchReportDetails(namespace, reportName, cluster) {
  if (!namespace || !reportName || !cluster) return null
  const response = await axios.get(`${apiBaseUrl}/report-details?namespace=${namespace}&reportName=${reportName}&cluster=${cluster}`)
  return response.data
}

export async function fetchClusters() {
  const response = await axios.get(`${apiBaseUrl}/clusters`)
  return response.data || []
}

export async function addCluster(clusterData) {
  const response = await axios.post(`${apiBaseUrl}/clusters`, clusterData)
  return response.data
}

export async function deleteCluster(clusterName) {
  const encodedName = encodeURIComponent(clusterName)
  const response = await axios.delete(`${apiBaseUrl}/clusters/${encodedName}`)
  return response.data
}

export async function updateCluster(clusterData) {
  console.log('Sending update request:', {
    url: `${apiBaseUrl}/clusters/${clusterData.name}`,
    data: {
      name: clusterData.name,
      kubeConfig: clusterData.kubeConfig ? 'present' : 'missing',
      enable: clusterData.enable
    }
  })
  const encodedName = encodeURIComponent(clusterData.name)
  const response = await axios.put(`${apiBaseUrl}/clusters/${encodedName}`, clusterData)
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