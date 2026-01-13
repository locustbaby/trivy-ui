import { useState, useEffect, useMemo, useCallback } from "react"
import { api, type Report } from "../api/client"
import { Button } from "./ui/button"
import { X, Loader2, Check, Share2 } from "lucide-react"
import { ReportInfoCard } from "./reports/ReportInfoCard"
import { SummaryCard } from "./reports/SummaryCard"
import { VulnerabilitySection } from "./reports/VulnerabilitySection"
import { ChecksSection } from "./reports/ChecksSection"

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

export function ReportDetails({
  typeName,
  reportName,
  cluster: _cluster,
  namespace: _namespace,
  onClose,
  shareUrl,
}: ReportDetailsProps) {
  const [report, setReport] = useState<Report | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>()
  const [copied, setCopied] = useState(false)

  // Retry handler
  const handleRetry = useCallback(() => {
    setError(undefined)
    setLoading(true)

    const controller = new AbortController()
    api.getReportDetails(typeName, reportName, controller.signal)
      .then((data) => {
        setReport(data)
        setLoading(false)
      })
      .catch((err) => {
        if (err instanceof Error && err.name === "AbortError") return
        setError(err instanceof Error ? err.message : "Failed to fetch report details")
        setLoading(false)
      })
  }, [typeName, reportName])

  useEffect(() => {
    const controller = new AbortController()

    // Reset state for new report
    setReport(null)
    setError(undefined)
    setLoading(true)

    api.getReportDetails(typeName, reportName, controller.signal)
      .then((data) => {
        setReport(data)
        setLoading(false)
      })
      .catch((err) => {
        // Ignore abort errors (happens in StrictMode cleanup)
        if (err instanceof Error && err.name === "AbortError") return
        setError(err instanceof Error ? err.message : "Failed to fetch report details")
        setLoading(false)
      })

    return () => {
      controller.abort()
    }
  }, [typeName, reportName])

  // Handle ESC key to close
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose()
      }
    }
    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
  }, [onClose])

  const handleCopyLink = useCallback(() => {
    if (shareUrl) {
      navigator.clipboard
        .writeText(shareUrl)
        .then(() => {
          setCopied(true)
          setTimeout(() => setCopied(false), 2000)
        })
        .catch((err) => {
          console.error("Failed to copy link:", err)
        })
    }
  }, [shareUrl])

  const displayTypeName = formatTypeName(typeName)

  // Memoized data extraction
  const reportData = useMemo(() => {
    if (!report?.data || typeof report.data !== "object") return null
    const data = report.data as any
    if (data.report && typeof data.report === "object") {
      return data.report
    }
    return data
  }, [report?.data])

  const summary = useMemo(() => {
    if (!reportData || typeof reportData !== "object") return null
    return reportData.summary || null
  }, [reportData])

  const artifact = useMemo(() => {
    if (!reportData || typeof reportData !== "object") return null
    return reportData.artifact || null
  }, [reportData])

  const vulnerabilities = useMemo(() => {
    if (!reportData || typeof reportData !== "object") return []
    const vulns = reportData.vulnerabilities
    if (Array.isArray(vulns)) {
      return vulns
    }
    return []
  }, [reportData])

  const hasVulnerabilitiesType = useMemo(() => {
    return vulnerabilities.length > 0
  }, [vulnerabilities])

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

  const checks = useMemo(() => {
    if (!reportData || typeof reportData !== "object") return []
    const checksData = reportData.checks
    if (Array.isArray(checksData)) {
      return checksData
    }
    return []
  }, [reportData])

  const scanner = useMemo(() => {
    if (!reportData || typeof reportData !== "object") return null
    return reportData.scanner || null
  }, [reportData])

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-4xl max-h-[90vh] rounded-2xl border bg-card shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b px-4 py-2.5 bg-gradient-to-r from-card to-muted/30">
          <div className="flex items-center gap-2 min-w-0">
            <div className="p-1.5 rounded-lg bg-primary/10 flex-shrink-0">
              <svg
                className="h-4 w-4 text-primary"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                />
              </svg>
            </div>
            <div className="min-w-0">
              <h2 className="text-base font-semibold leading-tight">{displayTypeName}</h2>
              <p className="text-xs text-muted-foreground truncate max-w-[400px]">
                {reportName}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-1.5 flex-shrink-0">
            {shareUrl && (
              <Button onClick={handleCopyLink} variant="outline" size="sm" className="gap-1.5 h-8 px-2.5">
                {copied ? (
                  <>
                    <Check className="h-3.5 w-3.5 text-green-500" />
                    <span className="text-xs">Copied</span>
                  </>
                ) : (
                  <>
                    <Share2 className="h-3.5 w-3.5" />
                    <span className="text-xs">Share</span>
                  </>
                )}
              </Button>
            )}
            <Button onClick={onClose} variant="ghost" size="icon" className="rounded-full h-8 w-8">
              <X className="h-4 w-4" />
            </Button>
          </div>
        </div>

        {/* Content */}
        <div className="overflow-y-auto p-4 max-h-[calc(90vh-56px)] scrollbar-thin">
          {loading && (
            <div className="flex flex-col items-center justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-primary mb-3" />
              <p className="text-sm text-muted-foreground">Loading report details...</p>
            </div>
          )}
          {error && (
            <div className="flex flex-col items-center justify-center py-12">
              <div className="p-3 rounded-full bg-destructive/10 mb-3">
                <X className="h-6 w-6 text-destructive" />
              </div>
              <div className="mb-3 text-sm text-destructive font-medium">Error: {error}</div>
              <Button onClick={handleRetry} size="sm">Retry</Button>
            </div>
          )}
          {report && !loading && !error && (
            <div className="space-y-3">
              <ReportInfoCard
                report={report}
                imageRef={imageRef}
                artifact={artifact}
                scanner={scanner}
                hasVulnerabilitiesType={hasVulnerabilitiesType}
              />

              {summary && <SummaryCard summary={summary} />}

              {hasVulnerabilitiesType && (
                <VulnerabilitySection vulnerabilities={vulnerabilities} />
              )}

              {checks.length > 0 && <ChecksSection checks={checks} />}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
