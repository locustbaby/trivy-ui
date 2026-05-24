const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ||
  (import.meta.env.DEV ? "http://localhost:8080" : "")

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
  syncState?: string
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
  withVulnerabilities?: number
  page: number
  pageSize: number
  data: T[]
}

export interface SeverityTotals {
  critical: number
  high: number
  medium: number
  low: number
}

export interface TypeBreakdown {
  scanned: number
  failed: number
  critical: number
}

export interface WorkloadSummary {
  cluster: string
  namespace: string
  name: string
  type: string
  critical: number
  high: number
}

export interface ClusterSummary {
  name: string
  critical: number
  high: number
}

export interface NamespaceSummary {
  name: string
  critical: number
  high: number
}

export interface ClusterOverview {
  total_reports: number
  severity_totals: SeverityTotals
  scan_types_breakdown: Record<string, TypeBreakdown>
  top_vulnerable_workloads: WorkloadSummary[]
  vulnerable_clusters?: ClusterSummary[]
  vulnerable_namespaces?: NamespaceSummary[]
}

export interface TrendRecord {
  timestamp: string
  cluster: string
  critical: number
  high: number
  medium: number
}

export const CLUSTER_SCOPED_NAMESPACE = "_"

async function fetchApi<T>(url: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${url}`, {
    cache: "no-store",
    signal,
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
  getOverview: (cluster?: string): Promise<ClusterOverview> => {
    const url = cluster ? `/api/v1/overview?cluster=${cluster}` : "/api/v1/overview"
    return fetchApi<ClusterOverview>(url)
  },

  getOverviewTrends: (cluster?: string, days: number = 30): Promise<TrendRecord[]> => {
    let url = `/api/v1/overview/trends?days=${days}`
    if (cluster) url += `&cluster=${cluster}`
    return fetchApi<TrendRecord[]>(url)
  },

  getClusters: (): Promise<Cluster[]> => {
    return fetchApi<Cluster[]>("/api/clusters")
  },

  getNamespacesByCluster: (cluster: string): Promise<Namespace[]> => {
    return fetchApi<Namespace[]>(`/api/clusters/${cluster}/namespaces`)
  },

  getTypes: (): Promise<ReportType[]> => {
    return fetchApi<ReportType[]>("/api/v1/type")
  },

  getReportsByType: (
    typeName: string,
    page?: number,
    pageSize?: number,
    cluster?: string,
    namespace?: string,
    search?: string,
    onlyVulnerable?: boolean
  ): Promise<PaginatedResponse<Report>> => {
    const params = new URLSearchParams()
    if (page) params.set("page", page.toString())
    if (pageSize) params.set("pageSize", pageSize.toString())
    if (cluster) params.set("cluster", cluster)
    if (namespace) params.set("namespace", namespace)
    if (search) params.set("search", search)
    if (onlyVulnerable !== undefined) params.set("onlyVulnerable", onlyVulnerable.toString())
    const query = params.toString()
    const url = `/api/v1/reports?type=${typeName}${query ? `&${query}` : ""}`
    return fetchApi<PaginatedResponse<Report>>(url)
  },

  getReportDetails: (
    cluster: string,
    namespace: string,
    typeName: string,
    reportName: string,
    signal?: AbortSignal
  ): Promise<Report> => {
    const namespaceSegment = namespace || CLUSTER_SCOPED_NAMESPACE
    const url = `/api/v1/reports/${encodeURIComponent(cluster)}/${encodeURIComponent(typeName)}/${encodeURIComponent(namespaceSegment)}/${encodeURIComponent(reportName)}`
    return fetchApi<Report>(url, signal)
  },
}
