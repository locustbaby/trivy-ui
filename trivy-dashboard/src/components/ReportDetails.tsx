import { useState, useEffect, useMemo } from "react"
import { api, type Report } from "../api/client"
import { Button } from "./ui/button"
import { X, Loader2, ExternalLink, Search, ChevronDown, ChevronUp } from "lucide-react"

interface ReportDetailsProps {
  typeName: string
  reportName: string
  onClose: () => void
}

function formatTypeName(name: string): string {
  let formatted = name.replace(/Report$/i, "")
  formatted = formatted.replace(/([a-z])([A-Z])/g, "$1 $2")
  formatted = formatted.replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
  return formatted.trim()
}

export function ReportDetails({ typeName, reportName, onClose }: ReportDetailsProps) {
  const [report, setReport] = useState<Report | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>()

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

  const displayTypeName = formatTypeName(typeName)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="relative w-full max-w-4xl max-h-[90vh] rounded-lg border bg-card shadow-lg">
        <div className="flex items-center justify-between border-b p-3">
          <h2 className="text-lg font-semibold">{displayTypeName}</h2>
          <Button onClick={onClose} variant="ghost" size="icon">
            <X className="h-4 w-4" />
          </Button>
        </div>
        <div className="overflow-y-auto p-4 max-h-[calc(90vh-80px)]">
          {loading && (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          )}
          {error && (
            <div className="flex flex-col items-center justify-center py-12">
              <div className="mb-4 text-destructive">Error: {error}</div>
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
    // Handle both structures: data.report (full K8s object) or data directly (simplified)
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

  // Check if this report type has vulnerabilities
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
        return "text-red-600"
      case "high":
        return "text-orange-600"
      case "medium":
        return "text-yellow-600"
      case "low":
        return "text-blue-600"
      default:
        return "text-gray-600"
    }
  }

  const getCheckSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case "critical":
        return "bg-red-50 border-red-200"
      case "high":
        return "bg-orange-50 border-orange-200"
      case "medium":
        return "bg-yellow-50 border-yellow-200"
      case "low":
        return "bg-blue-50 border-blue-200"
      default:
        return "bg-gray-50 border-gray-200"
    }
  }

  return (
    <div className="space-y-3">
      <div className="rounded-lg border bg-card p-4">
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <div className="text-xs font-medium text-muted-foreground mb-1.5">Name</div>
              <div className="text-sm font-semibold break-words">{report.name}</div>
            </div>
            <div>
              <div className="text-xs font-medium text-muted-foreground mb-1.5">Cluster</div>
              <div className="text-sm break-words">{report.cluster}</div>
            </div>
            {report.namespace && (
              <div>
                <div className="text-xs font-medium text-muted-foreground mb-1.5">Namespace</div>
                <div className="text-sm break-words">{report.namespace}</div>
              </div>
            )}
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {report.updated_at && (
              <div>
                <div className="text-xs font-medium text-muted-foreground mb-1.5">Updated At</div>
                <div className="text-sm">{new Date(report.updated_at).toLocaleString()}</div>
              </div>
            )}
            {hasVulnerabilitiesType && scanner && scanner.name && (
              <div>
                <div className="text-xs font-medium text-muted-foreground mb-1.5">Scanner</div>
                <div className="text-sm font-medium break-words">{scanner.name}</div>
              </div>
            )}
            {hasVulnerabilitiesType && scanner && scanner.version && (
              <div>
                <div className="text-xs font-medium text-muted-foreground mb-1.5">Scanner Version</div>
                <div className="text-sm font-medium break-words">{scanner.version}</div>
              </div>
            )}
          </div>

          {imageRef && (
            <div>
              <div className="text-xs font-medium text-muted-foreground mb-1.5">Image</div>
              <div className="text-sm font-medium break-all font-mono bg-muted/50 rounded px-2 py-1.5">{imageRef}</div>
            </div>
          )}

          {hasVulnerabilitiesType && artifact && artifact.digest && (
            <div>
              <div className="text-xs font-medium text-muted-foreground mb-1.5">Digest</div>
              <div className="text-xs font-mono break-all bg-muted/50 rounded px-2 py-1.5">{artifact.digest}</div>
            </div>
          )}
        </div>
      </div>

      {summary && (
        <div className="rounded-lg border bg-card p-3">
          <h3 className="text-base font-semibold mb-2">Summary</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
            {summary.criticalCount > 0 && (
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-red-600"></span>
                <div>
                  <div className="text-xs text-muted-foreground">Critical</div>
                  <div className="text-base font-semibold text-red-600">{summary.criticalCount}</div>
                </div>
              </div>
            )}
            {summary.highCount > 0 && (
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-orange-600"></span>
                <div>
                  <div className="text-xs text-muted-foreground">High</div>
                  <div className="text-base font-semibold text-orange-600">{summary.highCount}</div>
                </div>
              </div>
            )}
            {summary.mediumCount > 0 && (
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-yellow-600"></span>
                <div>
                  <div className="text-xs text-muted-foreground">Medium</div>
                  <div className="text-base font-semibold text-yellow-600">{summary.mediumCount}</div>
                </div>
              </div>
            )}
            {summary.lowCount > 0 && (
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-blue-600"></span>
                <div>
                  <div className="text-xs text-muted-foreground">Low</div>
                  <div className="text-base font-semibold text-blue-600">{summary.lowCount}</div>
                </div>
              </div>
            )}
            {summary.noneCount > 0 && (
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-green-600"></span>
                <div>
                  <div className="text-xs text-muted-foreground">None</div>
                  <div className="text-base font-semibold text-green-600">{summary.noneCount}</div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}


      {hasVulnerabilitiesType && (
        <div className="rounded-lg border bg-card p-3">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-base font-semibold">
              Vulnerabilities
              {allVulnerabilities.length > 0 && (
                <span className="ml-2 text-xs text-muted-foreground font-normal">
                  ({filteredVulnerabilities.length} / {allVulnerabilities.length})
                </span>
              )}
            </h3>
          </div>

          {allVulnerabilities.length === 0 ? (
            <div className="text-sm text-muted-foreground py-4 text-center">
              No vulnerabilities found
            </div>
          ) : (
            <>

          <div className="flex gap-2 mb-3">
            <div className="relative flex-1">
              <Search className="absolute left-2 top-1/2 transform -translate-y-1/2 h-3 w-3 text-muted-foreground pointer-events-none" />
              <input
                type="text"
                placeholder="Search CVE ID, title, or package..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-7 pr-2 h-7 text-xs rounded-md border border-input bg-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
              />
            </div>
            <div className="flex gap-1">
              {["all", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
                <Button
                  key={sev}
                  variant={severityFilter === sev ? "default" : "outline"}
                  size="sm"
                  onClick={() => setSeverityFilter(sev)}
                  className="h-7 text-[10px] px-2"
                >
                  {sev === "all" ? "All" : sev}
                </Button>
              ))}
            </div>
          </div>

          <div className="space-y-3 max-h-[600px] overflow-y-auto">
            {Object.entries(vulnerabilitiesBySeverity).map(([severity, vulns]) => {
              if (vulns.length === 0) return null

              const severityColors: Record<string, string> = {
                CRITICAL: "bg-red-50 border-red-200",
                HIGH: "bg-orange-50 border-orange-200",
                MEDIUM: "bg-yellow-50 border-yellow-200",
                LOW: "bg-blue-50 border-blue-200",
                UNKNOWN: "bg-gray-50 border-gray-200",
              }

              return (
                <div key={severity} className="space-y-2">
                  <div className={`flex items-center justify-between px-2 py-1 rounded ${severityColors[severity] || severityColors.UNKNOWN}`}>
                    <span className="text-xs font-semibold">
                      {severity} ({vulns.length})
                    </span>
                  </div>
                  <div className="space-y-1.5">
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
                          className={`border rounded p-2 ${getCheckSeverityColor(vuln.severity || "unknown")} cursor-pointer hover:shadow-sm transition-shadow`}
                          onClick={() => setExpandedCVE(isExpanded ? null : globalIndex)}
                        >
                          <div className="flex items-start justify-between">
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 mb-1">
                                <span className="font-semibold text-xs">{cveId}</span>
                                {vuln.primaryLink && (
                                  <a
                                    href={vuln.primaryLink}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    onClick={(e) => e.stopPropagation()}
                                    className="inline-flex items-center gap-0.5 text-[10px] text-blue-600 hover:text-blue-800 hover:underline"
                                  >
                                    <ExternalLink className="h-2.5 w-2.5" />
                                  </a>
                                )}
                                {cvssScore && (
                                  <span className="text-[10px] text-muted-foreground">
                                    CVSS: <span className="font-semibold">{cvssScore}</span>
                                  </span>
                                )}
                              </div>
                              {vuln.title && (
                                <div className="text-xs text-foreground mb-1 line-clamp-1">{vuln.title}</div>
                              )}
                              <div className="flex flex-wrap gap-x-3 gap-y-1 text-[10px] text-muted-foreground">
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
                                    <span className="font-mono text-green-600">{fixedVersion}</span>
                                  </span>
                                )}
                              </div>
                            </div>
                            <button className="ml-2 flex-shrink-0">
                              {isExpanded ? (
                                <ChevronUp className="h-3 w-3 text-muted-foreground" />
                              ) : (
                                <ChevronDown className="h-3 w-3 text-muted-foreground" />
                              )}
                            </button>
                          </div>

                          {isExpanded && (
                            <div className="mt-2 pt-2 border-t space-y-2">
                              {vuln.description && (
                                <div className="text-xs text-muted-foreground leading-relaxed">
                                  {vuln.description}
                                </div>
                              )}

                              <div className="grid grid-cols-2 gap-2 text-[10px]">
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
                                <div className="text-[10px]">
                                  <div className="font-medium text-muted-foreground mb-1">CVSS:</div>
                                  <div className="space-y-0.5">
                                    {vuln.cvss.nvd.V3Score && (
                                      <div>
                                        <span className="text-muted-foreground">v3.1: </span>
                                        <span className="font-semibold">{vuln.cvss.nvd.V3Score}</span>
                                      </div>
                                    )}
                                    {vuln.cvss.nvd.V2Score && (
                                      <div>
                                        <span className="text-muted-foreground">v2.0: </span>
                                        <span className="font-semibold">{vuln.cvss.nvd.V2Score}</span>
                                      </div>
                                    )}
                                  </div>
                                </div>
                              )}

                              {vuln.links && Array.isArray(vuln.links) && vuln.links.length > 0 && (
                                <div className="text-[10px]">
                                  <div className="font-medium text-muted-foreground mb-1">References:</div>
                                  <div className="flex flex-wrap gap-1">
                                    {vuln.links.slice(0, 5).map((link: string, linkIndex: number) => (
                                      <a
                                        key={linkIndex}
                                        href={link}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        onClick={(e) => e.stopPropagation()}
                                        className="inline-flex items-center gap-0.5 text-blue-600 hover:text-blue-800 hover:underline"
                                      >
                                        <ExternalLink className="h-2 w-2" />
                                        {link.length > 30 ? `${link.substring(0, 30)}...` : link}
                                      </a>
                                    ))}
                                    {vuln.links.length > 5 && (
                                      <span className="text-muted-foreground">+{vuln.links.length - 5} more</span>
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

      {allChecks.length > 0 && (
        <div className="rounded-lg border bg-card p-3">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-base font-semibold">
              Checks
              <span className="ml-2 text-xs text-muted-foreground font-normal">
                ({filteredChecks.length} / {allChecks.length})
              </span>
            </h3>
          </div>

          <div className="flex gap-2 mb-3">
            <div className="relative flex-1">
              <Search className="absolute left-2 top-1/2 transform -translate-y-1/2 h-3 w-3 text-muted-foreground pointer-events-none" />
              <input
                type="text"
                placeholder="Search check ID, title, description..."
                value={checkSearchQuery}
                onChange={(e) => setCheckSearchQuery(e.target.value)}
                className="w-full pl-7 pr-2 h-7 text-xs rounded-md border border-input bg-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
              />
            </div>
            <div className="flex gap-1">
              {["all", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
                <Button
                  key={sev}
                  variant={checkSeverityFilter === sev ? "default" : "outline"}
                  size="sm"
                  onClick={() => setCheckSeverityFilter(sev)}
                  className="h-7 text-[10px] px-2"
                >
                  {sev === "all" ? "All" : sev}
                </Button>
              ))}
            </div>
          </div>

          <div className="space-y-3 max-h-[600px] overflow-y-auto">
            {Object.entries(checksBySeverity).map(([severity, checkList]) => {
              if (checkList.length === 0) return null

              const severityColors: Record<string, string> = {
                CRITICAL: "bg-red-50 border-red-200",
                HIGH: "bg-orange-50 border-orange-200",
                MEDIUM: "bg-yellow-50 border-yellow-200",
                LOW: "bg-blue-50 border-blue-200",
                UNKNOWN: "bg-gray-50 border-gray-200",
              }

              return (
                <div key={severity} className="space-y-2">
                  <div className={`flex items-center justify-between px-2 py-1 rounded ${severityColors[severity] || severityColors.UNKNOWN}`}>
                    <span className="text-xs font-semibold">
                      {severity} ({checkList.length})
                    </span>
                  </div>
                  <div className="space-y-1.5">
                    {checkList.map((check: any) => {
                      const globalIndex = allChecks.indexOf(check)
                      const isExpanded = expandedCheck === globalIndex
                      const checkID = check.checkID || check.id || `Check-${globalIndex}`

                      return (
                        <div
                          key={globalIndex}
                          className={`border rounded p-3 text-left ${getCheckSeverityColor(check.severity || "unknown")} cursor-pointer hover:shadow-sm transition-shadow`}
                          onClick={() => setExpandedCheck(isExpanded ? null : globalIndex)}
                        >
                          <div className="flex items-start justify-between gap-2">
                            <div className="flex-1 min-w-0 text-left">
                              <div className="flex items-center gap-2 mb-1.5">
                                <span className="font-bold text-sm text-foreground">{checkID}</span>
                                {check.severity && (
                                  <span className={`text-xs font-semibold px-2 py-0.5 rounded ${getSeverityColor(check.severity)}`}>
                                    {check.severity.toUpperCase()}
                                  </span>
                                )}
                              </div>
                              {check.title && (
                                <div className="text-sm font-semibold text-foreground mb-1.5 line-clamp-2 text-left">{check.title}</div>
                              )}
                              {check.category && (
                                <div className="text-xs text-muted-foreground mb-1 text-left">
                                  Category: <span className="font-medium">{check.category}</span>
                                </div>
                              )}
                            </div>
                            <button className="ml-2 flex-shrink-0 mt-0.5">
                              {isExpanded ? (
                                <ChevronUp className="h-4 w-4 text-muted-foreground" />
                              ) : (
                                <ChevronDown className="h-4 w-4 text-muted-foreground" />
                              )}
                            </button>
                          </div>

                          {isExpanded && (
                            <div className="mt-3 pt-3 border-t space-y-3 text-left">
                              {check.description && (
                                <div className="text-sm text-foreground leading-relaxed text-left">
                                  {check.description}
                                </div>
                              )}
                              {check.remediation && (
                                <div className="text-left">
                                  <div className="text-sm font-semibold text-foreground mb-1.5 text-left">Remediation:</div>
                                  <div className="p-2 bg-muted rounded text-sm text-foreground leading-relaxed text-left">
                                    {check.remediation}
                                  </div>
                                </div>
                              )}
                              {check.success !== undefined && (
                                <div className="text-sm text-muted-foreground text-left">
                                  <span className="font-semibold">Success: </span>
                                  <span>{check.success ? "Yes" : "No"}</span>
                                </div>
                              )}
                              {check.messages && Array.isArray(check.messages) && check.messages.length > 0 && (
                                <div className="text-left">
                                  <div className="text-sm font-semibold text-foreground mb-1.5 text-left">Messages:</div>
                                  <div className="space-y-1.5">
                                    {check.messages.map((msg: string, msgIndex: number) => (
                                      <div key={msgIndex} className="text-sm text-muted-foreground pl-3 border-l-2 border-muted-foreground/30 leading-relaxed text-left">
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
