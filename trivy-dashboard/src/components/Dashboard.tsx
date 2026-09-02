import { useState, useEffect, useCallback, useRef, lazy, Suspense } from "react"
import { useSearchParams } from "react-router-dom"
import { Sidebar } from "./ui/sidebar"
import { Button } from "./ui/button"
import { ReportsList } from "./ReportsList"
import { api, ApiError, CLUSTER_SCOPED_NAMESPACE, type Report, type ReportType, type Cluster, type WorkloadSummary } from "../api/client"
import { getCachedFresh, setCached } from "../lib/apiCache"
import { toast } from "../lib/toast"
import { CustomErrorPage } from "./CustomErrorPage"
import { LogOut, Shield, Loader2, AlertTriangle } from "lucide-react"

const ReportDetails = lazy(() => import("./ReportDetails").then((module) => ({ default: module.ReportDetails })))
const OverviewDashboard = lazy(() => import("./OverviewDashboard").then((module) => ({ default: module.OverviewDashboard })))
const GlobalHub = lazy(() => import("./GlobalHub").then((module) => ({ default: module.GlobalHub })))

const METADATA_REFRESH_INTERVAL = 30000
const COUNTS_REFRESH_INTERVAL = 15000
// Must stay below METADATA_REFRESH_INTERVAL so polling always revalidates.
const METADATA_CACHE_TTL = 20000

// Shallow identity comparison for metadata arrays; keeps state identity stable
// across polls so memoized children do not re-render on unchanged data.
function sameMetadata<T>(a: T[], b: T[]): boolean {
  if (a === b) return true
  if (a.length !== b.length) return false
  return a.every((item, index) => item === b[index] || JSON.stringify(item) === JSON.stringify(b[index]))
}

interface DashboardProps {
  username?: string
  onLogout?: () => void
}

export function Dashboard({ username, onLogout }: DashboardProps) {
  const [searchParams, setSearchParams] = useSearchParams()
  const [clusters, setClusters] = useState<Cluster[]>([])
  const [reportTypes, setReportTypes] = useState<ReportType[]>([])
  const [reportCounts, setReportCounts] = useState<Record<string, number>>({})
  const [selectedReport, setSelectedReport] = useState<Report | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>()
  const [errorStatus, setErrorStatus] = useState<number>()
  const [metadataErrorForCluster, setMetadataError] = useState<string>()
  const selectedClusterRef = useRef<string | undefined>(undefined)
  const fetchGenerationRef = useRef(0)
  const activeFetchRef = useRef<AbortController | null>(null)
  const hasMetadataRef = useRef(false)
  const clustersRef = useRef<Cluster[]>([])

  // Get state from URL params
  const selectedCluster = searchParams.get("cluster") || undefined
  const selectedType = searchParams.get("type") || undefined
  const isSingleClusterMode = clusters.length <= 1
  const searchParamsRef = useRef(searchParams)
  searchParamsRef.current = searchParams

  useEffect(() => {
    selectedClusterRef.current = selectedCluster
  }, [selectedCluster])

  // Update URL params helper
  const updateUrlParams = useCallback((updates: Record<string, string | null>) => {
    setSearchParams(prev => {
      const newParams = new URLSearchParams(prev)
      Object.entries(updates).forEach(([key, value]) => {
        if (value === null || value === undefined || value === "") {
          newParams.delete(key)
        } else {
          newParams.set(key, value)
        }
      })
      return newParams
    }, { replace: true })
  }, [setSearchParams])

  // Handle cluster selection
  const handleSelectCluster = useCallback((cluster: string) => {
    // Counts belong to the previous cluster; drop them immediately so stale
    // badges never render next to the newly selected cluster.
    setReportCounts({})
    setMetadataError(undefined)
    updateUrlParams({
      cluster: cluster === "all" ? null : cluster,
      namespace: null,
      report: null,
      reportNamespace: null,
    })
  }, [updateUrlParams])

  // Handle type selection
  const handleSelectType = useCallback((type: string) => {
    updateUrlParams({
      type,
      namespace: null,
      search: null,
      report: null,
      reportNamespace: null,
    })
  }, [updateUrlParams])

  const initFromUrlParams = useCallback((clustersData: Cluster[]) => {
    const currentParams = searchParamsRef.current
    const urlCluster = currentParams.get("cluster")
    const urlType = currentParams.get("type")

    let finalCluster = urlCluster
    const finalType = urlType

    if (!finalCluster && clustersData.length === 1) {
      finalCluster = clustersData[0].name
    }

    const updates: Record<string, string | null> = {}
    if (!urlCluster && finalCluster) updates.cluster = finalCluster
    if (!urlType && finalType) updates.type = finalType

    if (Object.keys(updates).length > 0) {
      updateUrlParams(updates)
    }

    return { cluster: finalCluster, type: finalType }
  }, [updateUrlParams])

  useEffect(() => {
    const reportName = searchParams.get("report")
    if (!reportName || !selectedType || !selectedCluster) {
      setSelectedReport(null)
      return
    }
    setSelectedReport((current) => {
      const reportNamespaceParam = searchParams.get("reportNamespace")
      const nextNamespace = reportNamespaceParam === CLUSTER_SCOPED_NAMESPACE
        ? ""
        : (reportNamespaceParam ?? searchParams.get("namespace") ?? "")
      if (
        current &&
        current.type === selectedType &&
        current.cluster === selectedCluster &&
        current.name === reportName &&
        current.namespace === nextNamespace
      ) {
        return current
      }
      return {
        type: selectedType,
        cluster: selectedCluster,
        namespace: nextNamespace,
        name: reportName,
        data: {},
      }
    })
  }, [searchParams, selectedCluster, selectedType])

  const fetchData = useCallback(async (cluster: string | undefined, silent: boolean = false) => {
    const generation = ++fetchGenerationRef.current
    activeFetchRef.current?.abort()
    const controller = new AbortController()
    activeFetchRef.current = controller

    const initialLoad = !hasMetadataRef.current
    // Before any metadata has ever loaded there is no view to preserve, so a
    // "silent" poll must behave like the initial load (surface errors, clear
    // the spinner) instead of aborting it into a blank screen.
    const effectiveSilent = silent && !initialLoad
    if (initialLoad && !effectiveSilent) {
      setLoading(true)
      setErrorStatus(undefined)
    }
    if (!initialLoad && !effectiveSilent) {
      // Cluster switch: hydrate instantly from cached metadata so the sidebar
      // shows this cluster's data while the network request is in flight.
      const cachedClusters = getCachedFresh<Cluster[]>("clusters", METADATA_CACHE_TTL)
      const cachedTypes = getCachedFresh<ReportType[]>(`types:${cluster ?? ""}`, METADATA_CACHE_TTL)
      if (cachedClusters) {
        clustersRef.current = cachedClusters
        setClusters(cachedClusters)
        initFromUrlParams(cachedClusters)
      }
      if (cachedTypes) {
        setReportTypes(cachedTypes)
        setError(undefined)
      } else {
        // Never visited this cluster (or cache expired): showing the previous
        // cluster's types under the new cluster's header is worse than showing
        // an empty list for a moment.
        setReportTypes([])
        setMetadataError(cluster)
      }
    }
    try {
      const [clustersData, typesData] = await Promise.all([
        api.getClusters(controller.signal),
        api.getTypes(cluster, controller.signal),
      ])
      if (generation !== fetchGenerationRef.current) return
      setCached("clusters", clustersData)
      setCached(`types:${cluster ?? ""}`, typesData)
      clustersRef.current = sameMetadata(clustersRef.current, clustersData) ? clustersRef.current : clustersData
      setClusters(clustersRef.current)
      setReportTypes((current) => (sameMetadata(current, typesData) ? current : typesData))
      setError(undefined)
      setMetadataError(undefined)
      hasMetadataRef.current = true

      initFromUrlParams(clustersData)
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") return
      if (generation !== fetchGenerationRef.current) return
      // Only surface full-screen errors before any metadata has loaded. Once
      // content exists, background failures degrade to a staleness indicator.
      if (initialLoad && !effectiveSilent) {
        setError(err instanceof Error ? err.message : "Unknown error")
        setErrorStatus(err instanceof ApiError ? err.status : undefined)
      } else if (!effectiveSilent) {
        setMetadataError(cluster)
        toast("Could not refresh cluster data. Showing possibly stale results.", "error")
      }
    } finally {
      if (generation === fetchGenerationRef.current && initialLoad) {
        setLoading(false)
      }
    }
  }, [initFromUrlParams])

  const refreshReportCounts = useCallback(async (cluster: string, types: ReportType[]) => {
    if (!cluster || types.length === 0) {
      setReportCounts({})
      return
    }

    let overview: Awaited<ReturnType<typeof api.getOverview>>
    try {
      overview = await api.getOverview(cluster)
    } catch (err) {
      if (!(err instanceof Error && err.name === "AbortError")) {
        toast("Failed to update report counts. Retrying automatically.", "error")
      }
      return
    }

    if (selectedClusterRef.current !== cluster) {
      return
    }

    setReportCounts((current) => {
      const next = { ...current }
      let changed = false
      for (const type of types) {
        const count = overview.scan_types_breakdown[type.name]?.scanned ?? 0
        if (current[type.name] !== count) {
          next[type.name] = count
          changed = true
        }
      }
      return changed ? next : current
    })
  }, [])

  useEffect(() => {
    fetchData(selectedCluster)
  }, [fetchData, selectedCluster])

  const handleSelectReport = useCallback((report: Report) => {
    setSelectedReport(report)
    updateUrlParams({
      cluster: report.cluster,
      type: report.type,
      report: report.name,
      reportNamespace: report.namespace || CLUSTER_SCOPED_NAMESPACE,
    })
  }, [updateUrlParams])

  const handleCloseReportDetails = useCallback(() => {
    setSelectedReport(null)
    updateUrlParams({ report: null, reportNamespace: null })
  }, [updateUrlParams])

  const handleSelectNamespace = useCallback((ns: string) => {
    updateUrlParams({ type: "VulnerabilityReport", namespace: ns })
  }, [updateUrlParams])

  const handleSelectWorkload = useCallback((w: WorkloadSummary) => {
    updateUrlParams({
      type: w.type,
      report: w.name,
      reportNamespace: w.namespace || CLUSTER_SCOPED_NAMESPACE,
      cluster: w.cluster,
      namespace: null,
      search: null,
    })
  }, [updateUrlParams])

  useEffect(() => {
    if (!selectedCluster) {
      setReportCounts({})
      return
    }
    refreshReportCounts(selectedCluster, reportTypes)
  }, [selectedCluster, reportTypes, refreshReportCounts])

  useEffect(() => {
    const refresh = () => {
      fetchData(selectedCluster, true)
      if (selectedCluster) {
        refreshReportCounts(selectedCluster, reportTypes)
      }
    }

    const metadataTimer = window.setInterval(() => {
      if (document.visibilityState === "visible") {
        fetchData(selectedCluster, true)
      }
    }, METADATA_REFRESH_INTERVAL)

    const countsTimer = window.setInterval(() => {
      if (document.visibilityState === "visible" && selectedCluster) {
        refreshReportCounts(selectedCluster, reportTypes)
      }
    }, COUNTS_REFRESH_INTERVAL)

    const handleVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        refresh()
      }
    }

    window.addEventListener("focus", refresh)
    document.addEventListener("visibilitychange", handleVisibilityChange)

    return () => {
      window.clearInterval(metadataTimer)
      window.clearInterval(countsTimer)
      window.removeEventListener("focus", refresh)
      document.removeEventListener("visibilitychange", handleVisibilityChange)
    }
  }, [fetchData, selectedCluster, reportTypes, refreshReportCounts])

  const handleReportTotalChange = useCallback((typeName: string, total: number) => {
    setReportCounts((current) => {
      if (current[typeName] === total) {
        return current
      }
      return { ...current, [typeName]: total }
    })
  }, [])

  // Get current URL for sharing
  const getShareUrl = () => {
    return window.location.href
  }

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center bg-gradient-to-br from-background to-muted/50">
        <div className="flex flex-col items-center gap-4">
          <div className="relative">
            <Shield className="h-16 w-16 text-primary animate-pulse" />
            <Loader2 className="h-8 w-8 text-primary absolute bottom-0 right-0 animate-spin" />
          </div>
          <div className="text-lg font-medium text-muted-foreground">Loading Trivy Dashboard...</div>
        </div>
      </div>
    )
  }

  if (error) {
    const status = errorStatus
    return (
      <CustomErrorPage>
        <div className="flex h-screen items-center justify-center bg-gradient-to-br from-background to-muted/50">
          <div className="flex flex-col items-center gap-4 p-8 rounded-2xl bg-card border shadow-xl max-w-md">
            <Shield className="h-16 w-16 text-destructive" />
            <div className="text-center">
              <h2 className="text-xl font-semibold mb-2">
                {status === 403 ? "Access Denied" : status === 503 ? "Service Unavailable" : "Connection Error"}
              </h2>
              <p className="text-muted-foreground mb-4">{error}</p>
            </div>
            <Button onClick={() => fetchData(selectedCluster, false)} className="px-8">
              Try Again
            </Button>
          </div>
        </div>
      </CustomErrorPage>
    )
  }

  if (!selectedCluster && !isSingleClusterMode) {
    return (
      <div className="relative">
        {username && onLogout && <div className="absolute right-6 top-6 z-10"><Button variant="outline" size="sm" onClick={onLogout}><LogOut className="mr-2 h-4 w-4" />{username}</Button></div>}
        <Suspense fallback={<div className="flex h-screen items-center justify-center"><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></div>}>
          <GlobalHub clusters={clusters} onSelectCluster={handleSelectCluster} />
        </Suspense>
      </div>
    )
  }

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar
        clusters={clusters}
        reportTypes={reportTypes}
        reportCounts={reportCounts}
        selectedCluster={selectedCluster}
        selectedType={selectedType}
        isSingleClusterMode={isSingleClusterMode}
        onSelectCluster={handleSelectCluster}
        onSelectType={handleSelectType}
      />
      <main className="flex-1 overflow-y-auto p-6 bg-gradient-to-br from-background via-background to-muted/30 scrollbar-thin">
        <div className="mx-auto max-w-7xl">
          <header className="mb-5">
            <div className="flex flex-wrap items-end justify-between gap-4">
              <div className="flex flex-wrap items-end gap-x-4 gap-y-1">
              <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-primary to-purple-600">
                Security Dashboard
              </h1>
              <p className="pb-1 text-sm text-muted-foreground">
                Monitor and analyze security vulnerabilities across your clusters
              </p>
              </div>
              <div className="flex items-center gap-2">
                {metadataErrorForCluster && (
                  <button
                    onClick={() => fetchData(metadataErrorForCluster || selectedCluster, false)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-2.5 py-1.5 text-xs font-medium text-amber-700 transition-colors hover:bg-amber-500/20 dark:text-amber-300"
                    title="Click to retry loading cluster metadata"
                  >
                    <AlertTriangle className="h-3.5 w-3.5" />
                    Metadata may be outdated — retry
                  </button>
                )}
                {username && onLogout && <Button variant="outline" size="sm" onClick={onLogout}><LogOut className="mr-2 h-4 w-4" />{username}</Button>}
              </div>
            </div>
          </header>
          {selectedType ? (
            <ReportsList
                typeName={selectedType}
                reportTypes={reportTypes}
                selectedCluster={selectedCluster}
                isSingleClusterMode={isSingleClusterMode}
                onSelectReport={handleSelectReport}
                onTotalChange={handleReportTotalChange}
              />
          ) : (
            <Suspense fallback={<div className="flex h-[60vh] items-center justify-center"><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></div>}>
              <OverviewDashboard
                selectedCluster={selectedCluster}
                onSelectNamespace={handleSelectNamespace}
                onSelectWorkload={handleSelectWorkload}
                onSelectCluster={handleSelectCluster}
              />
            </Suspense>
          )}
        </div>
      </main>
      {selectedReport && (
        <Suspense fallback={null}>
          <ReportDetails
            typeName={selectedReport.type}
            reportName={selectedReport.name}
            cluster={selectedReport.cluster}
            namespace={selectedReport.namespace}
            isSingleClusterMode={isSingleClusterMode}
            onClose={handleCloseReportDetails}
            shareUrl={getShareUrl()}
          />
        </Suspense>
      )}
    </div>
  )
}
