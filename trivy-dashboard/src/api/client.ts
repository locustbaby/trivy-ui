const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8080"

export interface ApiResponse<T> {
  code: number
  message: string
  data?: T
}

export interface ReportType {
  name: string
  kind: string
  namespaced: boolean
  apiVersion: string
  shortName?: string
}

export interface Cluster {
  name: string
  description?: string
}

export interface Namespace {
  cluster: string
  name: string
  description?: string
}

export interface Report {
  type: string
  cluster: string
  namespace: string
  name: string
  status?: string
  data: any
  updated_at?: string
}

export interface PaginatedResponse<T> {
  total: number
  page: number
  pageSize: number
  data: T[]
}

async function fetchApi<T>(url: string): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${url}`, {
    cache: "no-store",
    headers: {
      "Cache-Control": "no-cache",
    },
  })
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`)
  }
  const result: ApiResponse<T> = await response.json()
  if (result.code !== 0) {
    throw new Error(result.message || "API error")
  }
  return result.data as T
}

export const api = {
  getClusters: (): Promise<Cluster[]> => {
    return fetchApi<Cluster[]>("/api/clusters")
  },

  getNamespacesByCluster: (cluster: string): Promise<Namespace[]> => {
    return fetchApi<Namespace[]>(`/api/clusters/${cluster}/namespaces`)
  },

  getTypes: (): Promise<ReportType[]> => {
    return fetchApi<ReportType[]>("/api/v1/type")
  },

  getReportsByType: (typeName: string, page?: number, pageSize?: number, cluster?: string, namespace?: string): Promise<PaginatedResponse<Report>> => {
    const params = new URLSearchParams()
    if (page) params.set("page", page.toString())
    if (pageSize) params.set("pageSize", pageSize.toString())
    if (cluster) params.set("cluster", cluster)
    if (namespace) params.set("namespace", namespace)
    const query = params.toString()
    const url = `/api/v1/type/${typeName}${query ? `?${query}` : ""}`
    return fetchApi<PaginatedResponse<Report>>(url)
  },

  getReportDetails: (typeName: string, reportName: string): Promise<Report> => {
    return fetchApi<Report>(`/api/v1/type/${typeName}/${reportName}`)
  },
}
