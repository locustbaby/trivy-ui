import { useState, useEffect, useMemo, useRef, useCallback } from "react"
import { api, type Report, type ReportType } from "../api/client"
import { Button } from "./ui/button"
import { MultiCombobox } from "./ui/multi-combobox"
import { Search, Loader2, ArrowUp, Copy, Check } from "lucide-react"

interface ReportsListProps {
  typeName: string
  reportTypes: ReportType[]
  selectedCluster?: string
  onSelectReport: (report: Report) => void
}

const PAGE_SIZE = 50

export function ReportsList({
  typeName,
  reportTypes,
  selectedCluster,
  onSelectReport,
}: ReportsListProps) {
  const [reports, setReports] = useState<Report[]>([])
  const [namespaces, setNamespaces] = useState<string[]>([])
  const [selectedNamespaces, setSelectedNamespaces] = useState<string[]>([])
  const [searchQuery, setSearchQuery] = useState<string>("")
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string>()
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [totalWithVulnerabilities, setTotalWithVulnerabilities] = useState(0)
  const [hasMore, setHasMore] = useState(false)
  const [showScrollTop, setShowScrollTop] = useState(false)
  const [showAllReports, setShowAllReports] = useState(false)
  const [copiedReportKey, setCopiedReportKey] = useState<string | null>(null)
  const observerTarget = useRef<HTMLDivElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)

  const scrollToTop = useCallback(() => {
    const scrollContainer = document.querySelector("main.overflow-y-auto")
    if (scrollContainer) {
      scrollContainer.scrollTo({ top: 0, behavior: "smooth" })
    } else {
      window.scrollTo({ top: 0, behavior: "smooth" })
    }
  }, [])

  useEffect(() => {
    const scrollContainer = document.querySelector("main.overflow-y-auto")
    if (!scrollContainer) return

    const handleScroll = () => {
      if (scrollContainer.scrollTop > 300) {
        setShowScrollTop(true)
      } else {
        setShowScrollTop(false)
      }
    }

    scrollContainer.addEventListener("scroll", handleScroll)
    return () => {
      scrollContainer.removeEventListener("scroll", handleScroll)
    }
  }, [])

  const reportType = reportTypes.find((t) => t.name === typeName)
  const isNamespaced = reportType?.namespaced ?? false

  const fetchReports = useCallback(async (pageNum: number, reset: boolean = false) => {
    try {
      if (reset) {
        setLoading(true)
      } else {
        setLoadingMore(true)
      }
      setError(undefined)
      // For cluster-scoped reports, don't pass namespace parameter
      const namespaceParams = isNamespaced && selectedNamespaces.length > 0 && !selectedNamespaces.includes("all")
        ? selectedNamespaces.join(",")
        : undefined
      const response = await api.getReportsByType(typeName, pageNum, PAGE_SIZE, selectedCluster || undefined, namespaceParams)
      setTotal(response.total)
      setTotalWithVulnerabilities(response.withVulnerabilities ?? 0)
      if (reset) {
        setReports(response.data)
      } else {
        setReports((prev) => [...prev, ...response.data])
      }
      setHasMore(response.data.length === PAGE_SIZE && (pageNum * PAGE_SIZE) < response.total)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch reports")
    } finally {
      setLoading(false)
      setLoadingMore(false)
    }
  }, [typeName, selectedCluster, selectedNamespaces])

  useEffect(() => {
    if (typeName) {
      initializedRef.current = false
      setPage(1)
      setReports([])
      setTotal(0)
      setHasMore(false)
      if (isNamespaced && selectedCluster) {
        fetchNamespaces()
      }
    }
  }, [typeName, selectedCluster, isNamespaced])

  const prevParamsRef = useRef<string>("")

  useEffect(() => {
    if (!typeName) return

    const currentParams = JSON.stringify({
      typeName,
      cluster: selectedCluster || "",
      namespaces: [...selectedNamespaces].sort(),
      namespacesLength: namespaces.length,
    })

    if (currentParams !== prevParamsRef.current) {
      if (!isNamespaced || namespaces.length > 0 || selectedNamespaces.length === 0) {
        fetchReports(1, true)
      }
      prevParamsRef.current = currentParams
    }
  }, [typeName, selectedCluster, selectedNamespaces, fetchReports, isNamespaced, namespaces.length])

  const initializedRef = useRef(false)
  useEffect(() => {
    if (namespaces.length === 0) return
    if (initializedRef.current) return

    const savedNamespaces = localStorage.getItem(`trivy-ui-selected-namespaces-${typeName}`)
    if (savedNamespaces) {
      try {
        const parsed = JSON.parse(savedNamespaces)
        if (Array.isArray(parsed)) {
          const valid = parsed.filter((ns) => ns === "all" || namespaces.includes(ns))
          if (valid.length > 0) {
            setSelectedNamespaces(valid)
            initializedRef.current = true
            return
          }
        }
      } catch (e) {
        // ignore parse error
      }
    }
    initializedRef.current = true
  }, [namespaces, typeName])

  useEffect(() => {
    if (selectedNamespaces.length > 0) {
      localStorage.setItem(`trivy-ui-selected-namespaces-${typeName}`, JSON.stringify(selectedNamespaces))
    }
  }, [selectedNamespaces, typeName])

  const fetchNamespaces = async () => {
    if (!selectedCluster) return
    try {
      const data = await api.getNamespacesByCluster(selectedCluster)
      const nsList = data.map((ns) => ns.name).sort()
      setNamespaces(nsList)
    } catch (err) {
      console.error("Failed to fetch namespaces:", err)
    }
  }


  const loadMore = useCallback(() => {
    if (!loadingMore && hasMore) {
      const nextPage = page + 1
      setPage(nextPage)
      fetchReports(nextPage, false)
    }
  }, [page, loadingMore, hasMore, fetchReports])

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting && hasMore && !loadingMore) {
          loadMore()
        }
      },
      { threshold: 0.1 }
    )

    const currentTarget = observerTarget.current
    if (currentTarget) {
      observer.observe(currentTarget)
    }

    return () => {
      if (currentTarget) {
        observer.unobserve(currentTarget)
      }
    }
  }, [loadMore, hasMore, loadingMore])

  const getSummaryCounts = (report: Report) => {
    if (!report.data || typeof report.data !== "object") return null
    const data = report.data as any

    let summary: any = null

    if (data.summary && typeof data.summary === "object") {
      summary = data.summary
    } else if (data.report && typeof data.report === "object" && data.report.summary) {
      summary = data.report.summary
    }

    if (summary && typeof summary === "object") {
      return {
        critical: summary.criticalCount || 0,
        high: summary.highCount || 0,
        medium: summary.mediumCount || 0,
        low: summary.lowCount || 0,
      }
    }
    return null
  }

  const hasVulnerabilities = (report: Report): boolean => {
    const counts = getSummaryCounts(report)
    if (!counts) return false
    return counts.critical > 0 || counts.high > 0 || counts.medium > 0 || counts.low > 0
  }

  const filteredReports = useMemo(() => {
    let filtered = reports

    if (!showAllReports) {
      filtered = filtered.filter((r) => hasVulnerabilities(r))
    }

    if (searchQuery) {
      const lowerQuery = searchQuery.toLowerCase()
      filtered = filtered.filter((r) => {
        return (
          r.name.toLowerCase().includes(lowerQuery) ||
          r.cluster.toLowerCase().includes(lowerQuery) ||
          (r.namespace || "").toLowerCase().includes(lowerQuery)
        )
      })
    }

    return filtered
  }, [reports, selectedNamespaces, searchQuery, isNamespaced, showAllReports])

  const namespaceOptions = useMemo(() => {
    return [
      { value: "all", label: "All Namespaces" },
      ...namespaces.map((ns) => ({ value: ns, label: ns })),
    ]
  }, [namespaces])

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-muted-foreground">Loading reports...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <div className="mb-4 text-destructive">Error: {error}</div>
        <Button onClick={() => fetchReports(1, true)}>Retry</Button>
      </div>
    )
  }

  return (
    <div className="space-y-4" ref={containerRef}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h2 className="text-xl font-semibold">Reports</h2>
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <span className="px-2 py-0.5 rounded-md bg-destructive/10 text-destructive font-medium">
              {totalWithVulnerabilities} with vulnerabilities
            </span>
            <span>/</span>
            <span>{total} total</span>
          </div>
        </div>
        <Button onClick={() => fetchReports(1, true)} variant="outline" size="sm">
          Refresh
        </Button>
      </div>

      <div className="flex gap-4 items-end">
        {isNamespaced && namespaces.length > 0 && (
          <div className="w-64">
            <label className="mb-2 block text-sm font-medium">Namespace</label>
            <MultiCombobox
              options={namespaceOptions}
              value={selectedNamespaces}
              onValueChange={setSelectedNamespaces}
              placeholder="Select namespaces..."
            />
          </div>
        )}
        <div className="flex-1">
          <label className="mb-2 block text-sm font-medium">Search</label>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <input
              type="text"
              className="w-full pl-10 pr-4 py-2 rounded-md border bg-background text-sm outline-none focus:ring-2 focus:ring-ring"
              placeholder="Search by name, cluster, namespace..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
        </div>
        <div className="flex items-end">
          <Button
            onClick={() => setShowAllReports(!showAllReports)}
            variant={showAllReports ? "default" : "secondary"}
            size="sm"
            className={`h-10 font-medium ${!showAllReports ? "bg-amber-100 hover:bg-amber-200 text-amber-800 border-amber-300 dark:bg-amber-900/30 dark:hover:bg-amber-900/50 dark:text-amber-200 dark:border-amber-700" : ""}`}
          >
            {showAllReports ? "✓ Showing All" : "⚠ Show All Reports"}
          </Button>
        </div>
      </div>

      {filteredReports.length === 0 ? (
        <div className="flex items-center justify-center py-12">
          <div className="text-muted-foreground">
            {reports.length === 0 ? "No reports found" : "No reports match the filter"}
          </div>
        </div>
      ) : (
        <>
          <div className="space-y-2">
            {filteredReports.map((report) => {
              const reportKey = `${report.cluster}-${report.namespace}-${report.name}`
              const shareUrl = report.namespace
                ? `${window.location.origin}/${report.cluster}/${report.type}/${report.namespace}/${report.name}`
                : `${window.location.origin}/${report.cluster}/${report.type}/${report.name}`
              const isCopied = copiedReportKey === reportKey

              const handleCopyLink = (e: React.MouseEvent) => {
                e.stopPropagation()
                navigator.clipboard.writeText(shareUrl)
                setCopiedReportKey(reportKey)
                setTimeout(() => setCopiedReportKey(null), 2000)
              }

              return (
                <button
                  key={reportKey}
                  onClick={() => onSelectReport(report)}
                  className="w-full rounded-lg border bg-card p-4 text-left transition-colors hover:bg-accent"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <span className="font-medium">{report.name}</span>
                        <button
                          onClick={handleCopyLink}
                          className="p-1 rounded hover:bg-accent-foreground/10 transition-colors"
                          title="Copy share link"
                        >
                          {isCopied ? (
                            <Check className="h-3 w-3 text-green-600" />
                          ) : (
                            <Copy className="h-3 w-3 text-muted-foreground" />
                          )}
                        </button>
                      </div>
                      <div className="flex flex-wrap gap-4 text-sm text-muted-foreground mb-2">
                        <span>Cluster: {report.cluster}</span>
                        {report.namespace && <span>Namespace: {report.namespace}</span>}
                        {report.updated_at && (
                          <span>Updated: {new Date(report.updated_at).toLocaleString()}</span>
                        )}
                      </div>
                      {(() => {
                        const counts = getSummaryCounts(report)
                        if (counts && (counts.critical > 0 || counts.high > 0 || counts.medium > 0 || counts.low > 0)) {
                          return (
                            <div className="flex items-center gap-3 text-xs">
                              {counts.critical > 0 && (
                                <span className="flex items-center gap-1">
                                  <span className="w-2 h-2 rounded-full bg-red-600"></span>
                                  <span className="font-medium text-red-600">Critical: {counts.critical}</span>
                                </span>
                              )}
                              {counts.high > 0 && (
                                <span className="flex items-center gap-1">
                                  <span className="w-2 h-2 rounded-full bg-orange-600"></span>
                                  <span className="font-medium text-orange-600">High: {counts.high}</span>
                                </span>
                              )}
                              {counts.medium > 0 && (
                                <span className="flex items-center gap-1">
                                  <span className="w-2 h-2 rounded-full bg-yellow-600"></span>
                                  <span className="font-medium text-yellow-600">Medium: {counts.medium}</span>
                                </span>
                              )}
                              {counts.low > 0 && (
                                <span className="flex items-center gap-1">
                                  <span className="w-2 h-2 rounded-full bg-blue-600"></span>
                                  <span className="font-medium text-blue-600">Low: {counts.low}</span>
                                </span>
                              )}
                            </div>
                          )
                        }
                        return null
                      })()}
                    </div>
                  </div>
                </button>
              )
            })}
          </div>
          {hasMore && (
            <div ref={observerTarget} className="flex items-center justify-center py-4">
              {loadingMore && (
                <div className="flex items-center gap-2 text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span>Loading more...</span>
                </div>
              )}
            </div>
          )}
        </>
      )}

      {showScrollTop && (
        <Button
          onClick={scrollToTop}
          className="fixed bottom-8 right-8 rounded-full w-12 h-12 shadow-lg z-40"
          size="icon"
          variant="default"
        >
          <ArrowUp className="h-5 w-5" />
        </Button>
      )}
    </div>
  )
}
