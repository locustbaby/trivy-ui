export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ||
  ""

export interface ApiResponse<T> {
  code: number
  message: string
  data?: T
  error?: {
    type?: string
    requestId?: string
  }
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
  observedAt?: string
  stale?: boolean
  dataComplete?: boolean
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
  resourceVersion?: string
  stale?: boolean
  data: unknown
  ref?: ReportRef
  updated_at?: string
}

export interface ReportRef {
  cluster: string
  namespace: string
  type: string
  name: string
}

export interface PaginatedResponse<T> {
  total: number
  withVulnerabilities?: number
  page: number
  pageSize: number
  hasNext?: boolean
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
  cluster?: string
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
  namespace?: string
  critical: number
  high: number
  medium: number
}

export const CLUSTER_SCOPED_NAMESPACE = "_"

export class ApiError extends Error {
  readonly status: number
  readonly type?: string
  readonly requestId?: string

  constructor(status: number, message: string, type?: string, requestId?: string) {
    super(message)
    this.name = "ApiError"
    this.status = status
    this.type = type
    this.requestId = requestId
  }
}

async function fetchApi<T>(url: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${url}`, {
    cache: "no-store",
    signal,
    credentials: "include",
    headers: {
      "Cache-Control": "no-cache",
    },
  })
  const result: ApiResponse<T> = await response.json().catch(() => ({
    code: 1,
    message: `HTTP error! status: ${response.status}`,
  }))
  if (!response.ok) {
    if (response.status === 401) {
      window.dispatchEvent(new CustomEvent("trivy-ui:auth-expired"))
    } else if (response.status === 403) {
      window.dispatchEvent(new CustomEvent("trivy-ui:access-denied"))
    } else if (response.status === 503) {
      window.dispatchEvent(new CustomEvent("trivy-ui:service-unavailable"))
    }
    throw new ApiError(response.status, result.message || `HTTP error! status: ${response.status}`, result.error?.type, result.error?.requestId)
  }
  if (result.code !== 0) {
    throw new ApiError(response.status, result.message || "API error", result.error?.type, result.error?.requestId)
  }
  return result.data as T
}

export interface AuthMe {
  enabled: boolean
  mode: "none" | "local"
  authenticated: boolean
  provider?: string
  methods?: string[]
  username?: string
  groups?: string[]
}

async function sendAuth<T>(url: string, body?: unknown): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${url}`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const result = await response.json().catch(() => ({ message: "Request failed" }))
  if (!response.ok) {
    if (response.status === 401) {
      window.dispatchEvent(new CustomEvent("trivy-ui:auth-expired"))
    } else if (response.status === 503) {
      window.dispatchEvent(new CustomEvent("trivy-ui:service-unavailable"))
    }
    throw new ApiError(response.status, result.message || `HTTP error! status: ${response.status}`, result.error?.type, result.error?.requestId)
  }
  return result.data as T
}

export const api = {
  getAuthMe: async (): Promise<AuthMe> => {
    const response = await fetch(`${API_BASE_URL}/api/v1/auth/me`, { credentials: "include", cache: "no-store" })
    const result: ApiResponse<AuthMe> = await response.json().catch(() => ({ message: "Request failed" }))
    if (!response.ok && response.status !== 401) {
      throw new ApiError(response.status, result.message || `HTTP error! status: ${response.status}`, result.error?.type, result.error?.requestId)
    }
    return result.data || { enabled: true, mode: "local", authenticated: false, provider: "local", methods: ["password"] }
  },

  login: (username: string, password: string) => sendAuth<{ username: string }>("/api/v1/auth/login", { username, password }),

  logout: () => sendAuth<void>("/api/v1/auth/logout"),

  getOverview: (cluster?: string, signal?: AbortSignal): Promise<ClusterOverview> => {
    const url = cluster ? `/api/v1/overview?cluster=${encodeURIComponent(cluster)}` : "/api/v1/overview"
    return fetchApi<ClusterOverview>(url, signal)
  },

  getOverviewTrends: (cluster?: string, days: number = 30, signal?: AbortSignal): Promise<TrendRecord[]> => {
    let url = `/api/v1/overview/trends?days=${days}`
    if (cluster) url += `&cluster=${encodeURIComponent(cluster)}`
    return fetchApi<TrendRecord[]>(url, signal)
  },

  getClusters: (signal?: AbortSignal): Promise<Cluster[]> => {
    return fetchApi<Cluster[]>("/api/v1/clusters", signal)
  },

  getNamespacesByCluster: (cluster: string): Promise<Namespace[]> => {
    return fetchApi<Namespace[]>(`/api/v1/clusters/${encodeURIComponent(cluster)}/namespaces`)
  },

  getTypes: (cluster?: string, signal?: AbortSignal): Promise<ReportType[]> => {
    const query = cluster ? `?cluster=${encodeURIComponent(cluster)}` : ""
    return fetchApi<ReportType[]>(`/api/v1/report-types${query}`, signal)
  },

  getReportsByType: (
    typeName: string,
    page?: number,
    pageSize?: number,
    cluster?: string,
    namespace?: string,
    search?: string,
    onlyVulnerable?: boolean,
    signal?: AbortSignal
  ): Promise<PaginatedResponse<Report>> => {
    const params = new URLSearchParams()
    if (page) params.set("page", page.toString())
    if (pageSize) params.set("pageSize", pageSize.toString())
    if (cluster) params.set("cluster", cluster)
    if (namespace) params.set("namespace", namespace)
    if (search) params.set("search", search)
    if (onlyVulnerable !== undefined) params.set("onlyVulnerable", onlyVulnerable.toString())
    const query = params.toString()
    const url = `/api/v1/reports?type=${encodeURIComponent(typeName)}${query ? `&${query}` : ""}`
    return fetchApi<PaginatedResponse<Report>>(url, signal)
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
