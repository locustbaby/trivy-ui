import { useState, useEffect, useCallback } from "react"
import { useSearchParams } from "react-router-dom"
import { Sidebar } from "./ui/sidebar"
import { Button } from "./ui/button"
import { ReportsList } from "./ReportsList"
import { ReportDetails } from "./ReportDetails"
import { api, type Report, type ReportType, type Cluster } from "../api/client"
import { Shield, Loader2 } from "lucide-react"

export function Dashboard() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [clusters, setClusters] = useState<Cluster[]>([])
  const [reportTypes, setReportTypes] = useState<ReportType[]>([])
  const [reportCounts, setReportCounts] = useState<Record<string, number>>({})
  const [selectedReport, setSelectedReport] = useState<Report | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>()

  // Get state from URL params
  const selectedCluster = searchParams.get("cluster") || undefined
  const selectedType = searchParams.get("type") || undefined

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
      cluster,
      // Reset namespace when cluster changes
      namespace: null,
      report: null
    })
  }, [updateUrlParams])

  // Handle type selection
  const handleSelectType = useCallback((type: string) => {
    updateUrlParams({
      type,
      // Reset namespace and search when type changes
      namespace: null,
      search: null,
      report: null
    })
  }, [updateUrlParams])

  // Load report from URL on initial load
  const loadReportFromUrl = useCallback(async (typeName: string, reportName: string) => {
    try {
      const report = await api.getReportDetails(typeName, reportName)
      setSelectedReport(report)
    } catch (err) {
      console.error("Failed to load report from URL:", err)
      // Clear report param if load fails
      updateUrlParams({ report: null, namespace: null })
    }
  }, [updateUrlParams])

  // Initialize from URL params after data loads
  const initFromUrlParams = useCallback((clustersData: Cluster[], typesData: ReportType[]) => {
    const urlCluster = searchParams.get("cluster")
    const urlType = searchParams.get("type")
    const urlReport = searchParams.get("report")

    let finalCluster = urlCluster
    let finalType = urlType

    // If no cluster in URL, use first available
    if (!finalCluster && clustersData.length > 0) {
      finalCluster = clustersData[0].name
    }

    // If no type in URL, use first available
    if (!finalType && typesData.length > 0) {
      finalType = typesData[0].name
    }

    // Update URL with defaults if needed
    const updates: Record<string, string | null> = {}
    if (!urlCluster && finalCluster) updates.cluster = finalCluster
    if (!urlType && finalType) updates.type = finalType

    if (Object.keys(updates).length > 0) {
      updateUrlParams(updates)
    }

    // Load report if specified in URL
    if (urlReport && finalType && finalCluster) {
      loadReportFromUrl(finalType, urlReport)
    }

    return { cluster: finalCluster, type: finalType }
  }, [searchParams, updateUrlParams, loadReportFromUrl])

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    try {
      setLoading(true)
      const [clustersData, typesData] = await Promise.all([
        api.getClusters(),
        api.getTypes(),
      ])
      setClusters(clustersData)
      setReportTypes(typesData)

      const { cluster } = initFromUrlParams(clustersData, typesData)

      if (cluster) {
        fetchReportCounts(typesData, cluster)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error")
    } finally {
      setLoading(false)
    }
  }

  const handleSelectReport = (report: Report) => {
    setSelectedReport(report)
    updateUrlParams({
      cluster: report.cluster,
      type: report.type,
      report: report.name,
      namespace: report.namespace || null
    })
  }

  const handleCloseReportDetails = () => {
    setSelectedReport(null)
    updateUrlParams({ report: null })
    // Keep namespace in URL if it was part of filtering
  }

  const fetchReportCounts = async (types: ReportType[], cluster?: string) => {
    if (!cluster) return

    const counts: Record<string, number> = {}
    await Promise.all(
      types.map(async (type) => {
        try {
          const response = await api.getReportsByType(type.name, 1, 1, cluster, undefined)
          counts[type.name] = response.total
        } catch (err) {
          counts[type.name] = 0
        }
      })
    )
    setReportCounts(counts)
  }

  // Refetch counts when cluster changes
  useEffect(() => {
    if (selectedCluster && reportTypes.length > 0) {
      fetchReportCounts(reportTypes, selectedCluster)
    }
  }, [selectedCluster, reportTypes])

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
          <Button onClick={fetchData} className="px-8">
            Try Again
          </Button>
        </div>
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
        onSelectCluster={handleSelectCluster}
        onSelectType={handleSelectType}
      />
      <main className="flex-1 overflow-y-auto p-6 bg-gradient-to-br from-background via-background to-muted/30 scrollbar-thin">
        <div className="mx-auto max-w-7xl">
          <header className="mb-8">
            <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-primary to-purple-600">
              Security Dashboard
            </h1>
            <p className="text-muted-foreground mt-1">
              Monitor and analyze security vulnerabilities across your clusters
            </p>
          </header>
          {selectedType ? (
            <ReportsList
              typeName={selectedType}
              reportTypes={reportTypes}
              selectedCluster={selectedCluster}
              onSelectReport={handleSelectReport}
            />
          ) : (
            <div className="rounded-2xl border bg-card/50 backdrop-blur p-12 text-center">
              <Shield className="h-16 w-16 mx-auto mb-4 text-muted-foreground/50" />
              <h3 className="text-lg font-medium mb-2">No Report Type Selected</h3>
              <p className="text-muted-foreground">Please select a report type from the sidebar to view reports</p>
            </div>
          )}
        </div>
      </main>
      {selectedReport && (
        <ReportDetails
          typeName={selectedReport.type}
          reportName={selectedReport.name}
          cluster={selectedReport.cluster}
          namespace={selectedReport.namespace}
          onClose={handleCloseReportDetails}
          shareUrl={getShareUrl()}
        />
      )}
    </div>
  )
}
