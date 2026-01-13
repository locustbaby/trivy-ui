import { useState, useEffect, useMemo } from "react"
import { api, type Report } from "../api/client"
import { Button } from "./ui/button"
import { X, Loader2, ExternalLink, Search, ChevronDown, ChevronUp, Check, Share2 } from "lucide-react"

interface ReportDetailsProps {
  typeName: string
  reportName: string
  cluster?: string
  namespace?: string
  onClose: () => void
  shareUrl?: string
}

function formatTypeName(name: string): string {
  let formatted = name.replace(/Report$/i, "")
  formatted = formatted.replace(/([a-z])([A-Z])/g, "$1 $2")
  formatted = formatted.replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
  return formatted.trim()
}

export function ReportDetails({ typeName, reportName, cluster: _cluster, namespace: _namespace, onClose, shareUrl }: ReportDetailsProps) {
  const [report, setReport] = useState<Report | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>()
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    fetchReportDetails()
  }, [typeName, reportName])

  const fetchReportDetails = async () => {
    try {
      setLoading(true)
      setError(undefined)
      const data = await api.getReportDetails(typeName, reportName)
      setReport(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch report details")
    } finally {
      setLoading(false)
    }
  }

  const handleCopyLink = () => {
    if (shareUrl) {
      navigator.clipboard.writeText(shareUrl).then(() => {
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
      })
    }
  }

  const displayTypeName = formatTypeName(typeName)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div
        className="relative w-full max-w-4xl max-h-[90vh] rounded-2xl border bg-card shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b p-4 bg-gradient-to-r from-card to-muted/30">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <svg className="h-5 w-5 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
            </div>
            <div>
              <h2 className="text-lg font-semibold">{displayTypeName}</h2>
              <p className="text-sm text-muted-foreground truncate max-w-[300px]">{reportName}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {shareUrl && (
              <Button
                onClick={handleCopyLink}
                variant="outline"
                size="sm"
                className="gap-2"
              >
                {copied ? (
                  <>
                    <Check className="h-4 w-4 text-green-500" />
                    Copied!
                  </>
                ) : (
                  <>
                    <Share2 className="h-4 w-4" />
                    Share
                  </>
                )}
              </Button>
            )}
            <Button onClick={onClose} variant="ghost" size="icon" className="rounded-full">
              <X className="h-5 w-5" />
            </Button>
          </div>
        </div>

        {/* Content */}
        <div className="overflow-y-auto p-5 max-h-[calc(90vh-80px)] scrollbar-thin">
          {loading && (
            <div className="flex flex-col items-center justify-center py-16">
              <Loader2 className="h-10 w-10 animate-spin text-primary mb-4" />
              <p className="text-muted-foreground">Loading report details...</p>
            </div>
          )}
          {error && (
            <div className="flex flex-col items-center justify-center py-16">
              <div className="p-4 rounded-full bg-destructive/10 mb-4">
                <X className="h-8 w-8 text-destructive" />
              </div>
              <div className="mb-4 text-destructive font-medium">Error: {error}</div>
              <Button onClick={fetchReportDetails}>Retry</Button>
            </div>
          )}
          {report && <ReportContent report={report} />}
        </div>
      </div>
    </div>
  )
}

function ReportContent({ report }: { report: Report }) {
  const [searchQuery, setSearchQuery] = useState("")
  const [severityFilter, setSeverityFilter] = useState<string>("all")
  const [expandedCVE, setExpandedCVE] = useState<number | null>(null)
  const [checkSearchQuery, setCheckSearchQuery] = useState("")
  const [checkSeverityFilter, setCheckSeverityFilter] = useState<string>("all")
  const [expandedCheck, setExpandedCheck] = useState<number | null>(null)

  const reportData = useMemo(() => {
    if (!report.data || typeof report.data !== "object") return null
    const data = report.data as any
    if (data.report && typeof data.report === "object") {
      return data.report
    }
    return data
  }, [report.data])

  const summary = useMemo(() => {
    if (!reportData || typeof reportData !== "object") return null
    return reportData.summary || null
  }, [reportData])

  const artifact = useMemo(() => {
    if (!reportData || typeof reportData !== "object") return null
    return reportData.artifact || null
  }, [reportData])

  const hasVulnerabilitiesType = useMemo(() => {
    const reportType = report.type?.toLowerCase() || ""
    return reportType.includes("vulnerability")
  }, [report.type])

  const registry = useMemo(() => {
    if (!reportData || typeof reportData !== "object") return null
    const registryObj = reportData.registry
    if (registryObj && typeof registryObj === "object") {
      return registryObj.server || null
    }
    return null
  }, [reportData])

  const imageRef = useMemo(() => {
    if (!hasVulnerabilitiesType || !artifact) return null
    const parts: string[] = []
    if (registry) {
      parts.push(registry)
    }
    if (artifact.repository) {
      parts.push(artifact.repository)
    }
    if (parts.length > 0 && artifact.tag) {
      return `${parts.join("/")}:${artifact.tag}`
    }
    return parts.length > 0 ? parts.join("/") : null
  }, [hasVulnerabilitiesType, artifact, registry])

  const allVulnerabilities = useMemo(() => {
    if (!reportData || typeof reportData !== "object") return []
    const vulns = reportData.vulnerabilities
    if (Array.isArray(vulns)) {
      return vulns
    }
    return []
  }, [reportData])

  const filteredVulnerabilities = useMemo(() => {
    let filtered = allVulnerabilities

    if (severityFilter !== "all") {
      filtered = filtered.filter((v: any) =>
        (v.severity || "").toLowerCase() === severityFilter.toLowerCase()
      )
    }

    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter((v: any) => {
        const cveId = (v.vulnerabilityID || v.id || "").toLowerCase()
        const title = (v.title || "").toLowerCase()
        const resource = (v.resource || v.packageName || "").toLowerCase()
        return cveId.includes(query) || title.includes(query) || resource.includes(query)
      })
    }

    return filtered
  }, [allVulnerabilities, severityFilter, searchQuery])

  const vulnerabilitiesBySeverity = useMemo(() => {
    const grouped: Record<string, any[]> = {
      CRITICAL: [],
      HIGH: [],
      MEDIUM: [],
      LOW: [],
      UNKNOWN: [],
    }

    filteredVulnerabilities.forEach((v: any) => {
      const severity = (v.severity || "UNKNOWN").toUpperCase()
      if (grouped[severity]) {
        grouped[severity].push(v)
      } else {
        grouped.UNKNOWN.push(v)
      }
    })

    return grouped
  }, [filteredVulnerabilities])

  const allChecks = useMemo(() => {
    if (!reportData || typeof reportData !== "object") return []
    const checksData = reportData.checks
    if (Array.isArray(checksData)) {
      return checksData
    }
    return []
  }, [reportData])

  const filteredChecks = useMemo(() => {
    let filtered = allChecks

    if (checkSeverityFilter !== "all") {
      filtered = filtered.filter((c: any) =>
        (c.severity || "").toLowerCase() === checkSeverityFilter.toLowerCase()
      )
    }

    if (checkSearchQuery.trim()) {
      const query = checkSearchQuery.toLowerCase()
      filtered = filtered.filter((c: any) => {
        const checkID = (c.checkID || c.id || "").toLowerCase()
        const title = (c.title || "").toLowerCase()
        const description = (c.description || "").toLowerCase()
        const category = (c.category || "").toLowerCase()
        return checkID.includes(query) || title.includes(query) || description.includes(query) || category.includes(query)
      })
    }

    return filtered
  }, [allChecks, checkSeverityFilter, checkSearchQuery])

  const checksBySeverity = useMemo(() => {
    const grouped: Record<string, any[]> = {
      CRITICAL: [],
      HIGH: [],
      MEDIUM: [],
      LOW: [],
      UNKNOWN: [],
    }

    filteredChecks.forEach((c: any) => {
      const severity = (c.severity || "UNKNOWN").toUpperCase()
      if (grouped[severity]) {
        grouped[severity].push(c)
      } else {
        grouped.UNKNOWN.push(c)
      }
    })

    return grouped
  }, [filteredChecks])

  const scanner = useMemo(() => {
    if (!reportData || typeof reportData !== "object") return null
    return reportData.scanner || null
  }, [reportData])

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case "critical":
        return "text-red-600 dark:text-red-400"
      case "high":
        return "text-orange-600 dark:text-orange-400"
      case "medium":
        return "text-yellow-600 dark:text-yellow-400"
      case "low":
        return "text-blue-600 dark:text-blue-400"
      default:
        return "text-gray-600 dark:text-gray-400"
    }
  }

  const getSeverityBgColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case "critical":
        return "bg-red-50 dark:bg-red-950/30 border-red-200 dark:border-red-900/50"
      case "high":
        return "bg-orange-50 dark:bg-orange-950/30 border-orange-200 dark:border-orange-900/50"
      case "medium":
        return "bg-yellow-50 dark:bg-yellow-950/30 border-yellow-200 dark:border-yellow-900/50"
      case "low":
        return "bg-blue-50 dark:bg-blue-950/30 border-blue-200 dark:border-blue-900/50"
      default:
        return "bg-gray-50 dark:bg-gray-900/30 border-gray-200 dark:border-gray-800"
    }
  }

  const getSeverityBadgeColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case "critical":
        return "bg-red-100 dark:bg-red-900/50 text-red-700 dark:text-red-300"
      case "high":
        return "bg-orange-100 dark:bg-orange-900/50 text-orange-700 dark:text-orange-300"
      case "medium":
        return "bg-yellow-100 dark:bg-yellow-900/50 text-yellow-700 dark:text-yellow-300"
      case "low":
        return "bg-blue-100 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300"
      default:
        return "bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300"
    }
  }

  return (
    <div className="space-y-4">
      {/* Report Info Card */}
      <div className="rounded-xl border bg-gradient-to-br from-card to-muted/20 p-5">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          <div>
            <div className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">Name</div>
            <div className="text-sm font-semibold break-words">{report.name}</div>
          </div>
          <div>
            <div className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">Cluster</div>
            <div className="text-sm break-words">{report.cluster}</div>
          </div>
          {report.namespace && (
            <div>
              <div className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">Namespace</div>
              <div className="text-sm break-words">{report.namespace}</div>
            </div>
          )}
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-5 mt-5 pt-5 border-t">
          {report.updated_at && (
            <div>
              <div className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">Updated At</div>
              <div className="text-sm">{new Date(report.updated_at).toLocaleString()}</div>
            </div>
          )}
          {hasVulnerabilitiesType && scanner && scanner.name && (
            <div>
              <div className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">Scanner</div>
              <div className="text-sm font-medium break-words">{scanner.name}</div>
            </div>
          )}
          {hasVulnerabilitiesType && scanner && scanner.version && (
            <div>
              <div className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">Scanner Version</div>
              <div className="text-sm font-medium break-words">{scanner.version}</div>
            </div>
          )}
        </div>

        {imageRef && (
          <div className="mt-5 pt-5 border-t">
            <div className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">Image</div>
            <div className="text-sm font-medium break-all font-mono bg-muted/50 rounded-lg px-3 py-2">{imageRef}</div>
          </div>
        )}

        {hasVulnerabilitiesType && artifact && artifact.digest && (
          <div className="mt-4">
            <div className="text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">Digest</div>
            <div className="text-xs font-mono break-all bg-muted/50 rounded-lg px-3 py-2">{artifact.digest}</div>
          </div>
        )}
      </div>

      {/* Summary Card */}
      {summary && (
        <div className="rounded-xl border bg-card p-5">
          <h3 className="text-base font-semibold mb-4 flex items-center gap-2">
            <svg className="h-5 w-5 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
            Summary
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {summary.criticalCount > 0 && (
              <div className="flex items-center gap-3 p-3 rounded-lg bg-red-50 dark:bg-red-950/30">
                <span className="w-3 h-3 rounded-full bg-red-500 severity-pulse" />
                <div>
                  <div className="text-2xl font-bold text-red-600 dark:text-red-400">{summary.criticalCount}</div>
                  <div className="text-xs text-muted-foreground">Critical</div>
                </div>
              </div>
            )}
            {summary.highCount > 0 && (
              <div className="flex items-center gap-3 p-3 rounded-lg bg-orange-50 dark:bg-orange-950/30">
                <span className="w-3 h-3 rounded-full bg-orange-500" />
                <div>
                  <div className="text-2xl font-bold text-orange-600 dark:text-orange-400">{summary.highCount}</div>
                  <div className="text-xs text-muted-foreground">High</div>
                </div>
              </div>
            )}
            {summary.mediumCount > 0 && (
              <div className="flex items-center gap-3 p-3 rounded-lg bg-yellow-50 dark:bg-yellow-950/30">
                <span className="w-3 h-3 rounded-full bg-yellow-500" />
                <div>
                  <div className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">{summary.mediumCount}</div>
                  <div className="text-xs text-muted-foreground">Medium</div>
                </div>
              </div>
            )}
            {summary.lowCount > 0 && (
              <div className="flex items-center gap-3 p-3 rounded-lg bg-blue-50 dark:bg-blue-950/30">
                <span className="w-3 h-3 rounded-full bg-blue-500" />
                <div>
                  <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">{summary.lowCount}</div>
                  <div className="text-xs text-muted-foreground">Low</div>
                </div>
              </div>
            )}
            {summary.noneCount > 0 && (
              <div className="flex items-center gap-3 p-3 rounded-lg bg-green-50 dark:bg-green-950/30">
                <span className="w-3 h-3 rounded-full bg-green-500" />
                <div>
                  <div className="text-2xl font-bold text-green-600 dark:text-green-400">{summary.noneCount}</div>
                  <div className="text-xs text-muted-foreground">None</div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Vulnerabilities Section */}
      {hasVulnerabilitiesType && (
        <div className="rounded-xl border bg-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-semibold flex items-center gap-2">
              <svg className="h-5 w-5 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              Vulnerabilities
              {allVulnerabilities.length > 0 && (
                <span className="ml-2 text-xs text-muted-foreground font-normal px-2 py-0.5 bg-muted rounded-full">
                  {filteredVulnerabilities.length} / {allVulnerabilities.length}
                </span>
              )}
            </h3>
          </div>

          {allVulnerabilities.length === 0 ? (
            <div className="text-sm text-muted-foreground py-8 text-center bg-muted/30 rounded-lg">
              <svg className="h-12 w-12 mx-auto mb-3 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              No vulnerabilities found
            </div>
          ) : (
            <>
              {/* Filters */}
              <div className="flex gap-3 mb-4">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
                  <input
                    type="text"
                    placeholder="Search CVE ID, title, or package..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full pl-9 pr-4 h-9 text-sm rounded-lg border border-input bg-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50"
                  />
                </div>
                <div className="flex gap-1">
                  {["all", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
                    <Button
                      key={sev}
                      variant={severityFilter === sev ? "default" : "outline"}
                      size="sm"
                      onClick={() => setSeverityFilter(sev)}
                      className="h-9 text-xs px-3"
                    >
                      {sev === "all" ? "All" : sev}
                    </Button>
                  ))}
                </div>
              </div>

              {/* Vulnerabilities List */}
              <div className="space-y-4 max-h-[500px] overflow-y-auto scrollbar-thin pr-1">
                {Object.entries(vulnerabilitiesBySeverity).map(([severity, vulns]) => {
                  if (vulns.length === 0) return null

                  return (
                    <div key={severity} className="space-y-2">
                      <div className={`flex items-center justify-between px-3 py-2 rounded-lg ${getSeverityBgColor(severity)}`}>
                        <span className={`text-sm font-semibold ${getSeverityColor(severity)}`}>
                          {severity} ({vulns.length})
                        </span>
                      </div>
                      <div className="space-y-2">
                        {vulns.map((vuln: any) => {
                          const globalIndex = allVulnerabilities.indexOf(vuln)
                          const isExpanded = expandedCVE === globalIndex
                          const cveId = vuln.vulnerabilityID || vuln.id || `VULN-${globalIndex}`
                          const cvssScore = vuln.score || (vuln.cvss?.nvd?.V3Score) || (vuln.cvss?.nvd?.V2Score) || null
                          const resource = vuln.resource || vuln.packageName || "Unknown"
                          const installedVersion = vuln.installedVersion || "N/A"
                          const fixedVersion = vuln.fixedVersion || "Not available"

                          return (
                            <div
                              key={globalIndex}
                              className={`border rounded-lg p-3 ${getSeverityBgColor(vuln.severity || "unknown")} cursor-pointer hover:shadow-md transition-all duration-200`}
                              onClick={() => setExpandedCVE(isExpanded ? null : globalIndex)}
                            >
                              <div className="flex items-start justify-between">
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-2 mb-1.5">
                                    <span className="font-semibold text-sm">{cveId}</span>
                                    {vuln.primaryLink && (
                                      <a
                                        href={vuln.primaryLink}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        onClick={(e) => e.stopPropagation()}
                                        className="inline-flex items-center gap-1 text-xs text-primary hover:text-primary/80 hover:underline"
                                      >
                                        <ExternalLink className="h-3 w-3" />
                                      </a>
                                    )}
                                    {cvssScore && (
                                      <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${getSeverityBadgeColor(vuln.severity)}`}>
                                        CVSS: {cvssScore}
                                      </span>
                                    )}
                                  </div>
                                  {vuln.title && (
                                    <div className="text-sm text-foreground mb-2 line-clamp-1">{vuln.title}</div>
                                  )}
                                  <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                                    <span>
                                      <span className="font-medium">Package: </span>
                                      <span className="font-mono">{resource}</span>
                                    </span>
                                    <span>
                                      <span className="font-medium">Installed: </span>
                                      <span className="font-mono">{installedVersion}</span>
                                    </span>
                                    {fixedVersion !== "Not available" && (
                                      <span>
                                        <span className="font-medium">Fixed: </span>
                                        <span className="font-mono text-green-600 dark:text-green-400">{fixedVersion}</span>
                                      </span>
                                    )}
                                  </div>
                                </div>
                                <button className="ml-3 flex-shrink-0 p-1 rounded hover:bg-black/5 dark:hover:bg-white/5">
                                  {isExpanded ? (
                                    <ChevronUp className="h-4 w-4 text-muted-foreground" />
                                  ) : (
                                    <ChevronDown className="h-4 w-4 text-muted-foreground" />
                                  )}
                                </button>
                              </div>

                              {isExpanded && (
                                <div className="mt-3 pt-3 border-t space-y-3">
                                  {vuln.description && (
                                    <div className="text-sm text-muted-foreground leading-relaxed">
                                      {vuln.description}
                                    </div>
                                  )}

                                  <div className="grid grid-cols-2 gap-3 text-xs">
                                    {vuln.publishedDate && (
                                      <div>
                                        <span className="text-muted-foreground">Published: </span>
                                        <span>{new Date(vuln.publishedDate).toLocaleDateString()}</span>
                                      </div>
                                    )}
                                    {vuln.lastModifiedDate && (
                                      <div>
                                        <span className="text-muted-foreground">Modified: </span>
                                        <span>{new Date(vuln.lastModifiedDate).toLocaleDateString()}</span>
                                      </div>
                                    )}
                                  </div>

                                  {vuln.cvss?.nvd && (
                                    <div className="text-xs">
                                      <div className="font-medium text-muted-foreground mb-1">CVSS Scores:</div>
                                      <div className="flex gap-4">
                                        {vuln.cvss.nvd.V3Score && (
                                          <span className="px-2 py-1 bg-muted rounded">
                                            v3.1: <span className="font-semibold">{vuln.cvss.nvd.V3Score}</span>
                                          </span>
                                        )}
                                        {vuln.cvss.nvd.V2Score && (
                                          <span className="px-2 py-1 bg-muted rounded">
                                            v2.0: <span className="font-semibold">{vuln.cvss.nvd.V2Score}</span>
                                          </span>
                                        )}
                                      </div>
                                    </div>
                                  )}

                                  {vuln.links && Array.isArray(vuln.links) && vuln.links.length > 0 && (
                                    <div className="text-xs">
                                      <div className="font-medium text-muted-foreground mb-2">References:</div>
                                      <div className="flex flex-wrap gap-2">
                                        {vuln.links.slice(0, 5).map((link: string, linkIndex: number) => (
                                          <a
                                            key={linkIndex}
                                            href={link}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            onClick={(e) => e.stopPropagation()}
                                            className="inline-flex items-center gap-1 px-2 py-1 bg-muted hover:bg-muted/80 rounded text-primary hover:text-primary/80"
                                          >
                                            <ExternalLink className="h-3 w-3" />
                                            <span className="truncate max-w-[200px]">{new URL(link).hostname}</span>
                                          </a>
                                        ))}
                                        {vuln.links.length > 5 && (
                                          <span className="px-2 py-1 text-muted-foreground">+{vuln.links.length - 5} more</span>
                                        )}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  )
                })}
              </div>
            </>
          )}
        </div>
      )}

      {/* Checks Section */}
      {allChecks.length > 0 && (
        <div className="rounded-xl border bg-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-semibold flex items-center gap-2">
              <svg className="h-5 w-5 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
              </svg>
              Checks
              <span className="ml-2 text-xs text-muted-foreground font-normal px-2 py-0.5 bg-muted rounded-full">
                {filteredChecks.length} / {allChecks.length}
              </span>
            </h3>
          </div>

          {/* Filters */}
          <div className="flex gap-3 mb-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
              <input
                type="text"
                placeholder="Search check ID, title, description..."
                value={checkSearchQuery}
                onChange={(e) => setCheckSearchQuery(e.target.value)}
                className="w-full pl-9 pr-4 h-9 text-sm rounded-lg border border-input bg-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50"
              />
            </div>
            <div className="flex gap-1">
              {["all", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
                <Button
                  key={sev}
                  variant={checkSeverityFilter === sev ? "default" : "outline"}
                  size="sm"
                  onClick={() => setCheckSeverityFilter(sev)}
                  className="h-9 text-xs px-3"
                >
                  {sev === "all" ? "All" : sev}
                </Button>
              ))}
            </div>
          </div>

          {/* Checks List */}
          <div className="space-y-4 max-h-[500px] overflow-y-auto scrollbar-thin pr-1">
            {Object.entries(checksBySeverity).map(([severity, checkList]) => {
              if (checkList.length === 0) return null

              return (
                <div key={severity} className="space-y-2">
                  <div className={`flex items-center justify-between px-3 py-2 rounded-lg ${getSeverityBgColor(severity)}`}>
                    <span className={`text-sm font-semibold ${getSeverityColor(severity)}`}>
                      {severity} ({checkList.length})
                    </span>
                  </div>
                  <div className="space-y-2">
                    {checkList.map((check: any) => {
                      const globalIndex = allChecks.indexOf(check)
                      const isExpanded = expandedCheck === globalIndex
                      const checkID = check.checkID || check.id || `Check-${globalIndex}`

                      return (
                        <div
                          key={globalIndex}
                          className={`border rounded-lg p-4 text-left ${getSeverityBgColor(check.severity || "unknown")} cursor-pointer hover:shadow-md transition-all duration-200`}
                          onClick={() => setExpandedCheck(isExpanded ? null : globalIndex)}
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div className="flex-1 min-w-0 text-left">
                              <div className="flex items-center gap-2 mb-2">
                                <span className="font-bold text-sm text-foreground">{checkID}</span>
                                {check.severity && (
                                  <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${getSeverityBadgeColor(check.severity)}`}>
                                    {check.severity.toUpperCase()}
                                  </span>
                                )}
                              </div>
                              {check.title && (
                                <div className="text-sm font-medium text-foreground mb-2 line-clamp-2 text-left">{check.title}</div>
                              )}
                              {check.category && (
                                <div className="text-xs text-muted-foreground text-left">
                                  Category: <span className="font-medium">{check.category}</span>
                                </div>
                              )}
                            </div>
                            <button className="ml-2 flex-shrink-0 p-1 rounded hover:bg-black/5 dark:hover:bg-white/5">
                              {isExpanded ? (
                                <ChevronUp className="h-4 w-4 text-muted-foreground" />
                              ) : (
                                <ChevronDown className="h-4 w-4 text-muted-foreground" />
                              )}
                            </button>
                          </div>

                          {isExpanded && (
                            <div className="mt-4 pt-4 border-t space-y-4 text-left">
                              {check.description && (
                                <div className="text-sm text-foreground leading-relaxed text-left">
                                  {check.description}
                                </div>
                              )}
                              {check.remediation && (
                                <div className="text-left">
                                  <div className="text-sm font-semibold text-foreground mb-2 text-left">Remediation:</div>
                                  <div className="p-3 bg-muted rounded-lg text-sm text-foreground leading-relaxed text-left">
                                    {check.remediation}
                                  </div>
                                </div>
                              )}
                              {check.success !== undefined && (
                                <div className="text-sm text-muted-foreground text-left">
                                  <span className="font-semibold">Success: </span>
                                  <span className={check.success ? "text-green-600 dark:text-green-400" : "text-red-600 dark:text-red-400"}>
                                    {check.success ? "Yes" : "No"}
                                  </span>
                                </div>
                              )}
                              {check.messages && Array.isArray(check.messages) && check.messages.length > 0 && (
                                <div className="text-left">
                                  <div className="text-sm font-semibold text-foreground mb-2 text-left">Messages:</div>
                                  <div className="space-y-2">
                                    {check.messages.map((msg: string, msgIndex: number) => (
                                      <div key={msgIndex} className="text-sm text-muted-foreground pl-3 border-l-2 border-primary/30 leading-relaxed text-left">
                                        {msg}
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      )
                    })}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
