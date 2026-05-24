import { useState, useEffect, useCallback, useRef } from "react"
import { useSearchParams } from "react-router-dom"
import { Sidebar } from "./ui/sidebar"
import { Button } from "./ui/button"
import { ReportsList } from "./ReportsList"
import { ReportDetails } from "./ReportDetails"
import { OverviewDashboard } from "./OverviewDashboard"
import { GlobalHub } from "./GlobalHub"
import { api, CLUSTER_SCOPED_NAMESPACE, type Report, type ReportType, type Cluster } from "../api/client"
import { Shield, Loader2 } from "lucide-react"

const METADATA_REFRESH_INTERVAL = 30000
const COUNTS_REFRESH_INTERVAL = 15000

export function Dashboard() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [clusters, setClusters] = useState<Cluster[]>([])
  const [reportTypes, setReportTypes] = useState<ReportType[]>([])
  const [reportCounts, setReportCounts] = useState<Record<string, number>>({})
  const [selectedReport, setSelectedReport] = useState<Report | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>()
  const selectedClusterRef = useRef<string | undefined>(undefined)

  // Get state from URL params
  const selectedCluster = searchParams.get("cluster") || undefined
  const selectedType = searchParams.get("type") || undefined
  const isSingleClusterMode = clusters.length <= 1

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

  const loadReportFromUrl = useCallback((typeName: string, reportName: string) => {
    const urlCluster = searchParams.get("cluster")
    const reportNamespaceParam = searchParams.get("reportNamespace")
    const urlNamespace = reportNamespaceParam === CLUSTER_SCOPED_NAMESPACE
      ? ""
      : (reportNamespaceParam ?? searchParams.get("namespace") ?? "")
    const minimalReport: Report = {
      type: typeName,
      cluster: urlCluster || "",
      namespace: urlNamespace,
      name: reportName,
      data: {},
    }
    setSelectedReport(minimalReport)
  }, [searchParams])

  const initFromUrlParams = useCallback((clustersData: Cluster[]) => {
    const urlCluster = searchParams.get("cluster")
    const urlType = searchParams.get("type")
    const urlReport = searchParams.get("report")

    let finalCluster = urlCluster
    let finalType = urlType

    if (!finalCluster && clustersData.length === 1) {
      finalCluster = clustersData[0].name
    }

    const updates: Record<string, string | null> = {}
    if (!urlCluster && finalCluster) updates.cluster = finalCluster
    if (!urlType && finalType) updates.type = finalType

    if (Object.keys(updates).length > 0) {
      updateUrlParams(updates)
    }

    if (urlReport && finalType && finalCluster) {
      loadReportFromUrl(finalType, urlReport)
    }

    return { cluster: finalCluster, type: finalType }
  }, [searchParams, updateUrlParams, loadReportFromUrl])

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

  const fetchData = useCallback(async (silent: boolean = false) => {
    try {
      if (!silent) {
        setLoading(true)
      }
      const [clustersData, typesData] = await Promise.all([
        api.getClusters(),
        api.getTypes(),
      ])
      setClusters(clustersData)
      setReportTypes(typesData)

      initFromUrlParams(clustersData)
    } catch (err) {
      if (!silent) {
        setError(err instanceof Error ? err.message : "Unknown error")
      }
    } finally {
      if (!silent) {
        setLoading(false)
      }
    }
  }, [initFromUrlParams])

  const refreshReportCounts = useCallback(async (cluster: string, types: ReportType[]) => {
    if (!cluster || types.length === 0) {
      setReportCounts({})
      return
    }

    const entries = await Promise.all(
      types.map(async (type) => {
        try {
          const response = await api.getReportsByType(type.name, 1, 1, cluster, undefined)
          return [type.name, response.total] as const
        } catch {
          return null
        }
      })
    )

    if (selectedClusterRef.current !== cluster) {
      return
    }

    setReportCounts((current) => {
      const next = { ...current }
      for (const entry of entries) {
        if (!entry) continue
        next[entry[0]] = entry[1]
      }
      return next
    })
  }, [])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  const handleSelectReport = (report: Report) => {
    setSelectedReport(report)
    updateUrlParams({
      cluster: report.cluster,
      type: report.type,
      report: report.name,
      reportNamespace: report.namespace || CLUSTER_SCOPED_NAMESPACE,
    })
  }

  const handleCloseReportDetails = () => {
    setSelectedReport(null)
    updateUrlParams({ report: null, reportNamespace: null })
  }

  useEffect(() => {
    if (!selectedCluster) {
      setReportCounts({})
      return
    }
    refreshReportCounts(selectedCluster, reportTypes)
  }, [selectedCluster, reportTypes, refreshReportCounts])

  useEffect(() => {
    const refresh = () => {
      fetchData(true)
      if (selectedCluster) {
        refreshReportCounts(selectedCluster, reportTypes)
      }
    }

    const metadataTimer = window.setInterval(() => {
      if (document.visibilityState === "visible") {
        fetchData(true)
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
    return (
      <div className="flex h-screen items-center justify-center bg-gradient-to-br from-background to-muted/50">
        <div className="flex flex-col items-center gap-4 p-8 rounded-2xl bg-card border shadow-xl max-w-md">
          <Shield className="h-16 w-16 text-destructive" />
          <div className="text-center">
            <h2 className="text-xl font-semibold mb-2">Connection Error</h2>
            <p className="text-muted-foreground mb-4">{error}</p>
          </div>
          <Button onClick={() => fetchData(false)} className="px-8">
            Try Again
          </Button>
        </div>
      </div>
    )
  }

  if (!selectedCluster && !isSingleClusterMode) {
    return <GlobalHub clusters={clusters} onSelectCluster={handleSelectCluster} />
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
            <div className="flex flex-wrap items-end gap-x-4 gap-y-1">
              <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-primary to-purple-600">
                Security Dashboard
              </h1>
              <p className="pb-1 text-sm text-muted-foreground">
                Monitor and analyze security vulnerabilities across your clusters
              </p>
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
            <OverviewDashboard
              selectedCluster={selectedCluster}
              onSelectNamespace={(ns) => updateUrlParams({ type: "VulnerabilityReport", namespace: ns })}
              onSelectWorkload={(w) => updateUrlParams({ type: w.type, report: w.name, reportNamespace: w.namespace, cluster: w.cluster })}
              onSelectCluster={handleSelectCluster}
            />
          )}
        </div>
      </main>
      {selectedReport && (
        <ReportDetails
          typeName={selectedReport.type}
          reportName={selectedReport.name}
          cluster={selectedReport.cluster}
          namespace={selectedReport.namespace}
          isSingleClusterMode={isSingleClusterMode}
          onClose={handleCloseReportDetails}
          shareUrl={getShareUrl()}
        />
      )}
    </div>
  )
}
