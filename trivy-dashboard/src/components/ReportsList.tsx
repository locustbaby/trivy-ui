import { useState, useEffect, useMemo, useRef, useCallback } from "react"
import { useSearchParams } from "react-router-dom"
import { api, type Report, type ReportType } from "../api/client"
import { Button } from "./ui/button"
import { MultiCombobox } from "./ui/multi-combobox"
import { Search, Loader2, ArrowUp, Share2, Check, Shield, AlertTriangle, X } from "lucide-react"

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
  const [searchParams, setSearchParams] = useSearchParams()

  // Get filter state from URL - these are the source of truth
  const urlNamespaces = searchParams.get("namespace")
  const urlSearch = searchParams.get("search") || ""
  const urlShowAll = searchParams.get("showAll") !== "false" // default true

  // Parse URL namespaces once
  const initialNamespaces = useMemo(() => {
    if (urlNamespaces) {
      return urlNamespaces.split(",").filter(Boolean)
    }
    return []
  }, [urlNamespaces])

  const [reports, setReports] = useState<Report[]>([])
  const [namespaces, setNamespaces] = useState<string[]>([])
  const [selectedNamespaces, setSelectedNamespaces] = useState<string[]>(initialNamespaces)
  const [searchQuery, setSearchQuery] = useState<string>(urlSearch)
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string>()
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [hasMore, setHasMore] = useState(false)
  const [showScrollTop, setShowScrollTop] = useState(false)
  const [showAllReports, setShowAllReports] = useState(urlShowAll)
  const [copiedReportId, setCopiedReportId] = useState<string | null>(null)
  const [copiedField, setCopiedField] = useState<string | null>(null)
  const [namespacesLoaded, setNamespacesLoaded] = useState(false)
  const observerTarget = useRef<HTMLDivElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const isFirstLoad = useRef(true)
  const fetchInProgressRef = useRef<string | null>(null) // Track current fetch to prevent duplicates

  const reportType = reportTypes.find((t) => t.name === typeName)
  const isNamespaced = reportType?.namespaced ?? false

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

  // Sync namespace selection to URL and localStorage
  const handleNamespaceChange = useCallback((namespaces: string[]) => {
    setSelectedNamespaces(namespaces)
    const hasAll = namespaces.includes("all")
    updateUrlParams({
      namespace: hasAll || namespaces.length === 0 ? null : namespaces.join(",")
    })
    // Save to localStorage
    if (typeName && selectedCluster && isNamespaced) {
      localStorage.setItem(`trivy-ui-selected-namespaces-${typeName}-${selectedCluster}`, JSON.stringify(namespaces))
    }
  }, [updateUrlParams, typeName, selectedCluster, isNamespaced])

  // Sync search to URL with debounce
  const searchTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Cleanup timeout on unmount
  useEffect(() => {
    return () => {
      if (searchTimeoutRef.current) {
        clearTimeout(searchTimeoutRef.current)
      }
    }
  }, [])

  const handleSearchChange = useCallback((value: string) => {
    setSearchQuery(value)

    // Debounce URL update
    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current)
    }
    searchTimeoutRef.current = setTimeout(() => {
      updateUrlParams({ search: value || null })
    }, 300)
  }, [updateUrlParams])

  // Sync showAll filter to URL
  const handleShowAllChange = useCallback((showAll: boolean) => {
    setShowAllReports(showAll)
    updateUrlParams({ showAll: showAll ? null : "false" }) // only store when false
  }, [updateUrlParams])

  const copyReportLink = useCallback((report: Report, e: React.MouseEvent) => {
    e.stopPropagation()
    const url = new URL(window.location.href)
    url.searchParams.set("cluster", report.cluster)
    url.searchParams.set("type", report.type)
    url.searchParams.set("report", report.name)
    if (report.namespace) {
      url.searchParams.set("namespace", report.namespace)
    } else {
      url.searchParams.delete("namespace")
    }
    // Remove filter params for clean share URL
    url.searchParams.delete("search")
    url.searchParams.delete("showAll")

    navigator.clipboard
      .writeText(url.toString())
      .then(() => {
        const reportId = `${report.cluster}-${report.namespace}-${report.name}`
        setCopiedReportId(reportId)
        setTimeout(() => setCopiedReportId(null), 2000)
      })
      .catch((err) => {
        console.error("Failed to copy link:", err)
      })
  }, [])

  const copyToClipboard = useCallback((text: string, fieldId: string, e: React.MouseEvent) => {
    e.stopPropagation()
    navigator.clipboard
      .writeText(text)
      .then(() => {
        setCopiedField(fieldId)
        setTimeout(() => setCopiedField(null), 1500)
      })
      .catch((err) => {
        console.error("Failed to copy:", err)
      })
  }, [])

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

  // Fetch reports - this now uses URL namespace directly for initial load
  const fetchReports = useCallback(async (pageNum: number, reset: boolean = false, overrideNamespaces?: string[]) => {
    // Use override namespaces if provided, otherwise use selected namespaces
    const namespacesToUse = overrideNamespaces ?? selectedNamespaces
    const namespaceParams = isNamespaced && namespacesToUse.length > 0 && !namespacesToUse.includes("all")
      ? namespacesToUse.join(",")
      : undefined

    // Create a unique key for this request to prevent duplicates
    const requestKey = `${typeName}-${selectedCluster}-${namespaceParams}-${pageNum}-${reset}`

    // Skip if the same request is already in progress
    if (fetchInProgressRef.current === requestKey) {
      return
    }

    try {
      fetchInProgressRef.current = requestKey

      if (reset) {
        setLoading(true)
      } else {
        setLoadingMore(true)
      }
      setError(undefined)

      const response = await api.getReportsByType(typeName, pageNum, PAGE_SIZE, selectedCluster || undefined, namespaceParams)
      setTotal(response.total)
      if (reset) {
        setReports(response.data)
      } else {
        // Deduplicate when loading more
        setReports((prev) => {
          const existingKeys = new Set(prev.map(r => `${r.cluster}-${r.namespace}-${r.name}`))
          const newReports = response.data.filter(r => !existingKeys.has(`${r.cluster}-${r.namespace}-${r.name}`))
          return [...prev, ...newReports]
        })
      }
      setHasMore(response.data.length === PAGE_SIZE && (pageNum * PAGE_SIZE) < response.total)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch reports")
    } finally {
      setLoading(false)
      setLoadingMore(false)
      fetchInProgressRef.current = null
    }
  }, [typeName, selectedCluster, selectedNamespaces, isNamespaced])

  // Fetch namespaces for the cluster
  const fetchNamespaces = useCallback(async (): Promise<string[]> => {
    if (!selectedCluster) return []
    try {
      const data = await api.getNamespacesByCluster(selectedCluster)
      const nsList = data.map((ns) => ns.name).sort()
      setNamespaces(nsList)
      setNamespacesLoaded(true)
      return nsList
    } catch (err) {
      console.error("Failed to fetch namespaces:", err)
      setNamespacesLoaded(true)
      return []
    }
  }, [selectedCluster])

  // Reset and initialize when type or cluster changes
  // Note: Only depend on typeName, selectedCluster, isNamespaced - NOT on callback functions
  // This prevents re-fetching when unrelated URL params change (like closing report details)
  useEffect(() => {
    if (!typeName) return

    isFirstLoad.current = true
    setPage(1)
    setReports([])
    setTotal(0)
    setHasMore(false)
    setNamespacesLoaded(false)

    if (isNamespaced && selectedCluster) {
      fetchNamespaces().then((availableNamespaces) => {
        const urlNs = searchParams.get("namespace")
        const urlNsArray = urlNs ? urlNs.split(",").filter(Boolean) : []

        // Validate URL namespaces against available namespaces
        const validUrlNs = urlNsArray.filter((ns) => ns === "all" || availableNamespaces.includes(ns))

        let namespacesToUse: string[] = []
        if (validUrlNs.length > 0) {
          // Use URL namespace if valid
          namespacesToUse = validUrlNs
        } else {
          // Otherwise, load from localStorage for current type
          const savedNs = localStorage.getItem(`trivy-ui-selected-namespaces-${typeName}-${selectedCluster}`)
          if (savedNs) {
            try {
              const parsed = JSON.parse(savedNs)
              if (Array.isArray(parsed)) {
                namespacesToUse = parsed.filter((ns) => ns === "all" || availableNamespaces.includes(ns))
              }
            } catch (e) {
              // ignore parse error
            }
          }
        }
        // Always set selectedNamespaces and update URL, even if empty
        setSelectedNamespaces(namespacesToUse)
        updateUrlParams({ namespace: namespacesToUse.length > 0 && !namespacesToUse.includes("all") ? namespacesToUse.join(",") : null })
        fetchReports(1, true, namespacesToUse)
        isFirstLoad.current = false
      })
    } else {
      // For non-namespaced types, clear namespace selection and URL
      setSelectedNamespaces([])
      updateUrlParams({ namespace: null })
      fetchReports(1, true, [])
      isFirstLoad.current = false
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [typeName, selectedCluster, isNamespaced])

  // Handle subsequent namespace changes (after initial load)
  const prevNamespacesRef = useRef<string>("")
  useEffect(() => {
    if (isFirstLoad.current) return
    if (!namespacesLoaded && isNamespaced) return

    const currentNs = JSON.stringify([...selectedNamespaces].sort())
    if (currentNs !== prevNamespacesRef.current) {
      prevNamespacesRef.current = currentNs
      setPage(1)
      setHasMore(false) // Reset hasMore when namespace changes
      fetchReports(1, true)
    }
  }, [selectedNamespaces, namespacesLoaded, isNamespaced, fetchReports])

  const loadMore = useCallback(() => {
    if (!loadingMore && hasMore) {
      const nextPage = page + 1
      setPage(nextPage)
      fetchReports(nextPage, false)
    }
  }, [page, loadingMore, hasMore, fetchReports])

  useEffect(() => {
    if (!hasMore) return // Don't set up observer if there's no more data

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

    // Sort for stable results: cluster -> namespace -> name
    filtered = [...filtered].sort((a, b) => {
      // 1. Sort by cluster
      const clusterCompare = a.cluster.localeCompare(b.cluster)
      if (clusterCompare !== 0) return clusterCompare
      // 2. Sort by namespace (empty namespace goes last)
      const nsA = a.namespace || "\uffff" // Use high unicode char to sort empty last
      const nsB = b.namespace || "\uffff"
      const nsCompare = nsA.localeCompare(nsB)
      if (nsCompare !== 0) return nsCompare
      // 3. Sort by name
      return a.name.localeCompare(b.name)
    })

    return filtered
  }, [reports, searchQuery, showAllReports])

  const namespaceOptions = useMemo(() => {
    return [
      { value: "all", label: "All Namespaces" },
      ...namespaces.map((ns) => ({ value: ns, label: ns })),
    ]
  }, [namespaces])

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-16">
        <Loader2 className="h-10 w-10 text-primary animate-spin mb-4" />
        <div className="text-muted-foreground font-medium">Loading reports...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center py-16">
        <AlertTriangle className="h-12 w-12 text-destructive mb-4" />
        <div className="mb-4 text-destructive font-medium">Error: {error}</div>
        <Button onClick={() => fetchReports(1, true)}>Retry</Button>
      </div>
    )
  }

  return (
    <div className="space-y-6" ref={containerRef}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Reports</h2>
          <p className="text-sm text-muted-foreground mt-1">
            {showAllReports ? (
              <>
                Showing <span className="font-semibold text-foreground">{filteredReports.length}</span>
                {hasMore && <span> (loaded {reports.length})</span>}
                {total > 0 && <span> of {total} total</span>}
              </>
            ) : (
              <>
                Showing <span className="font-semibold text-foreground">{filteredReports.length}</span>
                <span> with issues</span>
                {hasMore && <span> (loaded {reports.length})</span>}
                {total > 0 && <span className="text-muted-foreground/70"> / {total} total</span>}
              </>
            )}
          </p>
        </div>
        <Button onClick={() => fetchReports(1, true)} variant="outline" size="sm" className="gap-2">
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          Refresh
        </Button>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4 items-stretch sm:items-end">
        {isNamespaced && (
          <div className="w-full sm:w-64">
            <label className="mb-2 block text-sm font-medium text-muted-foreground">Namespace</label>
            {!namespacesLoaded ? (
              <div className="h-11 rounded-xl border bg-muted animate-pulse flex items-center justify-center">
                <span className="text-sm text-muted-foreground">Loading namespaces...</span>
              </div>
            ) : namespaces.length > 0 ? (
              <MultiCombobox
                options={namespaceOptions}
                value={selectedNamespaces}
                onValueChange={handleNamespaceChange}
                placeholder="Select namespaces..."
              />
            ) : (
              <div className="h-11 rounded-xl border bg-muted flex items-center justify-center">
                <span className="text-sm text-muted-foreground">No namespaces available</span>
              </div>
            )}
          </div>
        )}
        <div className="flex-1 min-w-0 sm:min-w-[200px]">
          <label className="mb-2 block text-sm font-medium text-muted-foreground">Search</label>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <input
              type="text"
              className="w-full pl-10 pr-10 py-2.5 rounded-xl border bg-background text-sm outline-none focus:ring-2 focus:ring-primary/50 transition-shadow"
              placeholder="Search by name, cluster, namespace..."
              value={searchQuery}
              onChange={(e) => handleSearchChange(e.target.value)}
            />
            {searchQuery && (
              <button
                onClick={() => handleSearchChange("")}
                className="absolute right-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground hover:text-foreground transition-colors"
                title="Clear search"
              >
                <X className="h-4 w-4" />
              </button>
            )}
          </div>
        </div>
        <div className="flex items-stretch sm:items-end gap-2">
          <Button
            onClick={() => handleShowAllChange(!showAllReports)}
            variant={showAllReports ? "outline" : "default"}
            size="sm"
            className="h-11 px-4 gap-2 flex-1 sm:flex-initial"
            title={showAllReports ? "Show only vulnerable" : "Show all reports"}
          >
            {showAllReports ? (
              <>
                <Shield className="h-4 w-4" />
                <span className="hidden sm:inline">All</span>
                <span className="sm:hidden">All</span>
              </>
            ) : (
              <>
                <AlertTriangle className="h-4 w-4" />
                <span className="hidden sm:inline">Vulnerable</span>
                <span className="sm:hidden">Vuln</span>
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Reports Grid */}
      {filteredReports.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 rounded-2xl border bg-card/50">
          <Shield className="h-16 w-16 text-muted-foreground/30 mb-4" />
          <div className="text-lg font-medium text-muted-foreground">
            {reports.length === 0 ? "No reports found" : "No reports match the filter"}
          </div>
          <p className="text-sm text-muted-foreground/70 mt-1">
            Try adjusting your search or filter criteria
          </p>
        </div>
      ) : (
        <>
          <div className="grid gap-3">
            {filteredReports.map((report) => {
              const reportId = `${report.cluster}-${report.namespace}-${report.name}`
              const counts = getSummaryCounts(report)
              const hasSeverity = counts && (counts.critical > 0 || counts.high > 0 || counts.medium > 0 || counts.low > 0)

              return (
                <div
                  key={reportId}
                  className="group relative rounded-xl border bg-card p-4 transition-all duration-200 hover:shadow-lg hover:border-primary/30 hover:-translate-y-0.5 cursor-pointer"
                  onClick={() => onSelectReport(report)}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3 mb-2">
                        <span className="font-semibold text-base truncate">{report.name}</span>
                        {hasSeverity && (
                          <div className="flex items-center gap-1.5">
                            {counts.critical > 0 && (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-red-100 dark:bg-red-950/50 text-red-700 dark:text-red-400 text-xs font-medium">
                                <span className="w-1.5 h-1.5 rounded-full bg-red-500 severity-pulse" />
                                {counts.critical}
                              </span>
                            )}
                            {counts.high > 0 && (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-orange-100 dark:bg-orange-950/50 text-orange-700 dark:text-orange-400 text-xs font-medium">
                                <span className="w-1.5 h-1.5 rounded-full bg-orange-500" />
                                {counts.high}
                              </span>
                            )}
                            {counts.medium > 0 && (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-yellow-100 dark:bg-yellow-950/50 text-yellow-700 dark:text-yellow-400 text-xs font-medium">
                                <span className="w-1.5 h-1.5 rounded-full bg-yellow-500" />
                                {counts.medium}
                              </span>
                            )}
                            {counts.low > 0 && (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-blue-100 dark:bg-blue-950/50 text-blue-700 dark:text-blue-400 text-xs font-medium">
                                <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />
                                {counts.low}
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                      <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm text-muted-foreground">
                        <button
                          onClick={(e) => copyToClipboard(report.cluster, `cluster-${reportId}`, e)}
                          className="inline-flex items-center gap-1 hover:text-foreground transition-colors cursor-pointer"
                          title="Click to copy cluster name"
                        >
                          {copiedField === `cluster-${reportId}` ? (
                            <Check className="h-3.5 w-3.5 text-green-500" />
                          ) : (
                            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
                            </svg>
                          )}
                          <span className={copiedField === `cluster-${reportId}` ? "text-green-500" : ""}>{report.cluster}</span>
                        </button>
                        {report.namespace && (
                          <button
                            onClick={(e) => copyToClipboard(report.namespace!, `ns-${reportId}`, e)}
                            className="inline-flex items-center gap-1 hover:text-foreground transition-colors cursor-pointer"
                            title="Click to copy namespace"
                          >
                            {copiedField === `ns-${reportId}` ? (
                              <Check className="h-3.5 w-3.5 text-green-500" />
                            ) : (
                              <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                              </svg>
                            )}
                            <span className={copiedField === `ns-${reportId}` ? "text-green-500" : ""}>{report.namespace}</span>
                          </button>
                        )}
                        {report.updated_at && (
                          <span className="inline-flex items-center gap-1">
                            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            {new Date(report.updated_at).toLocaleString()}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Share Button */}
                    <button
                      onClick={(e) => copyReportLink(report, e)}
                      className="opacity-0 group-hover:opacity-100 transition-opacity p-2 rounded-lg hover:bg-muted text-muted-foreground hover:text-foreground"
                      title="Copy link to this report"
                    >
                      {copiedReportId === reportId ? (
                        <Check className="h-4 w-4 text-green-500" />
                      ) : (
                        <Share2 className="h-4 w-4" />
                      )}
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
          {hasMore && (
            <div ref={observerTarget} className="flex items-center justify-center py-6">
              {loadingMore && (
                <div className="flex items-center gap-3 text-muted-foreground">
                  <Loader2 className="h-5 w-5 animate-spin" />
                  <span>Loading more...</span>
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* Scroll to Top Button */}
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
