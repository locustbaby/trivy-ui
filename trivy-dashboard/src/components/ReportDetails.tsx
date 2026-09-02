import { useState, useEffect, useMemo, useCallback, useRef } from "react"
import { api, ApiError, type Report } from "../api/client"
import { Button } from "./ui/button"
import { X, Loader2, Check, Share2 } from "lucide-react"
import { ReportInfoCard } from "./reports/ReportInfoCard"
import { SummaryCard } from "./reports/SummaryCard"
import { VulnerabilitySection, type Vulnerability } from "./reports/VulnerabilitySection"
import { ChecksSection, type Check as ReportCheck } from "./reports/ChecksSection"
import { formatReportTypeName } from "../lib/utils"
import { toast } from "../lib/toast"

const DETAIL_REFRESH_INTERVAL = 15000

type JsonObject = Record<string, unknown>

interface Summary {
  criticalCount?: number
  highCount?: number
  mediumCount?: number
  lowCount?: number
  noneCount?: number
}

interface ReportDetailsProps {
  typeName: string
  reportName: string
  cluster?: string
  namespace?: string
  isSingleClusterMode?: boolean
  onClose: () => void
  shareUrl?: string
}

export function ReportDetails({
  typeName,
  reportName,
  cluster,
  namespace,
  isSingleClusterMode = false,
  onClose,
  shareUrl,
}: ReportDetailsProps) {
  const [report, setReport] = useState<Report | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>()
  const [errorStatus, setErrorStatus] = useState<number>()
  const [copied, setCopied] = useState(false)
  const requestGenerationRef = useRef(0)
  const activeRequestRef = useRef<AbortController | null>(null)

  const loadReport = useCallback((showLoading: boolean, replaceReport: boolean = false) => {
    const generation = ++requestGenerationRef.current
    activeRequestRef.current?.abort()
    const controller = new AbortController()
    activeRequestRef.current = controller
    setError(undefined)
    setErrorStatus(undefined)
    if (showLoading) {
      setLoading(true)
    }
    if (replaceReport) {
      setReport(null)
    }

    api.getReportDetails(cluster || "", namespace || "", typeName, reportName, controller.signal)
      .then((data) => {
        if (generation !== requestGenerationRef.current) return
        setReport(data)
        setLoading(false)
      })
      .catch((err) => {
        if (err instanceof Error && err.name === "AbortError") return
        if (generation !== requestGenerationRef.current) return
        const message = err instanceof Error ? err.message : "Failed to fetch report details"
        if (showLoading) {
          setError(message)
          setErrorStatus(err instanceof ApiError ? err.status : undefined)
        } else {
          // Background refresh failed; surface it without wiping the view.
          toast(`Could not refresh report details: ${message}`, "error")
        }
        setLoading(false)
      })
      .finally(() => {
        if (generation === requestGenerationRef.current) {
          activeRequestRef.current = null
        }
      })
  }, [cluster, namespace, typeName, reportName])

  const handleRetry = useCallback(() => {
    loadReport(true, false)
  }, [loadReport])

  useEffect(() => {
    let cancelled = false
    void Promise.resolve().then(() => {
      if (!cancelled) loadReport(true, true)
    })

    return () => {
      cancelled = true
      requestGenerationRef.current += 1
      activeRequestRef.current?.abort()
    }
  }, [loadReport])

  useEffect(() => {
    const refresh = () => {
      loadReport(false, false)
    }

    const runRefresh = () => {
      refresh()
    }

    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") {
        runRefresh()
      }
    }, DETAIL_REFRESH_INTERVAL)

    const handleVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        runRefresh()
      }
    }

    window.addEventListener("focus", runRefresh)
    document.addEventListener("visibilitychange", handleVisibilityChange)

    return () => {
      requestGenerationRef.current += 1
      activeRequestRef.current?.abort()
      window.clearInterval(timer)
      window.removeEventListener("focus", runRefresh)
      document.removeEventListener("visibilitychange", handleVisibilityChange)
    }
  }, [loadReport])

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

  const displayTypeName = formatReportTypeName(typeName)

  // Memoized data extraction
  const reportData = useMemo<JsonObject | null>(() => {
    if (!report?.data || typeof report.data !== "object") return null
    const data = report.data as JsonObject
    if (data.report && typeof data.report === "object" && !Array.isArray(data.report)) {
      return data.report as JsonObject
    }
    return data
  }, [report?.data])

  const summary = useMemo(() => {
    if (!reportData || typeof reportData !== "object") return null
    return reportData.summary && typeof reportData.summary === "object"
      ? reportData.summary as Summary
      : null
  }, [reportData])

  const artifact = useMemo(() => {
    if (!reportData || typeof reportData !== "object") return null
    return reportData.artifact && typeof reportData.artifact === "object"
      ? reportData.artifact as JsonObject
      : null
  }, [reportData])

  const vulnerabilities = useMemo(() => {
    if (!reportData || typeof reportData !== "object") return []
    const vulns = reportData.vulnerabilities
    if (Array.isArray(vulns)) {
      return vulns as Vulnerability[]
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
      const server = (registryObj as JsonObject).server
      return typeof server === "string" ? server : null
    }
    return null
  }, [reportData])

  const imageRef = useMemo(() => {
    if (!hasVulnerabilitiesType || !artifact) return null
    const parts: string[] = []
    if (registry) {
      parts.push(registry)
    }
    if (typeof artifact.repository === "string") {
      parts.push(artifact.repository)
    }
    if (parts.length > 0 && typeof artifact.tag === "string") {
      return `${parts.join("/")}:${artifact.tag}`
    }
    return parts.length > 0 ? parts.join("/") : null
  }, [hasVulnerabilitiesType, artifact, registry])

  const checks = useMemo(() => {
    if (!reportData || typeof reportData !== "object") return []
    const checksData = reportData.checks
    if (Array.isArray(checksData)) {
      return checksData as ReportCheck[]
    }
    return []
  }, [reportData])

  const scanner = useMemo(() => {
    if (!reportData || typeof reportData !== "object") return null
    return reportData.scanner && typeof reportData.scanner === "object"
      ? reportData.scanner as JsonObject
      : null
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
              <div className="mb-3 text-sm text-destructive font-medium">
                {errorStatus === 403 ? "Access denied" : errorStatus === 503 ? "Service unavailable" : `Error: ${error}`}
              </div>
              <Button onClick={handleRetry} size="sm">Retry</Button>
            </div>
          )}
          {report && !loading && !error && (
            <div className="space-y-3">
              {report.stale && (
                <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-700 dark:text-amber-300">
                  This detail is from the local cache and may be stale because the cluster is currently unavailable.
                </div>
              )}
              <ReportInfoCard
                report={report}
                imageRef={imageRef}
                artifact={artifact}
                scanner={scanner}
                hasVulnerabilitiesType={hasVulnerabilitiesType}
                isSingleClusterMode={isSingleClusterMode}
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
