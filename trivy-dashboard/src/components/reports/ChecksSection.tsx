import { useState, useMemo } from "react"
import { Button } from "../ui/button"
import { Search, ChevronDown, ChevronUp, ChevronsUpDown } from "lucide-react"
import { getSeverityColor, getSeverityBgColor, getSeverityBadgeColor } from "../../lib/severity"

interface Check {
  checkID?: string
  id?: string
  title?: string
  description?: string
  severity?: string
  category?: string
  success?: boolean
  remediation?: string
  messages?: string[]
}

interface ChecksSectionProps {
  checks: Check[]
}

export function ChecksSection({ checks }: ChecksSectionProps) {
  const [searchQuery, setSearchQuery] = useState("")
  const [severityFilter, setSeverityFilter] = useState<string>("all")
  const [expandedCheck, setExpandedCheck] = useState<string | null>(null)
  const [expandAll, setExpandAll] = useState(false)

  const filteredChecks = useMemo(() => {
    let filtered = checks

    if (severityFilter !== "all") {
      filtered = filtered.filter(
        (c) => (c.severity || "").toLowerCase() === severityFilter.toLowerCase()
      )
    }

    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter((c) => {
        const checkID = (c.checkID || c.id || "").toLowerCase()
        const title = (c.title || "").toLowerCase()
        const description = (c.description || "").toLowerCase()
        const category = (c.category || "").toLowerCase()
        return (
          checkID.includes(query) ||
          title.includes(query) ||
          description.includes(query) ||
          category.includes(query)
        )
      })
    }

    return filtered
  }, [checks, severityFilter, searchQuery])

  const checksBySeverity = useMemo(() => {
    const grouped: Record<string, Check[]> = {
      CRITICAL: [],
      HIGH: [],
      MEDIUM: [],
      LOW: [],
      UNKNOWN: [],
    }

    filteredChecks.forEach((c) => {
      const severity = (c.severity || "UNKNOWN").toUpperCase()
      if (grouped[severity]) {
        grouped[severity].push(c)
      } else {
        grouped.UNKNOWN.push(c)
      }
    })

    return grouped
  }, [filteredChecks])

  const handleToggle = (checkId: string) => {
    if (expandAll) {
      setExpandAll(false)
      setExpandedCheck(checkId)
    } else {
      setExpandedCheck(expandedCheck === checkId ? null : checkId)
    }
  }

  const isExpanded = (checkId: string) => {
    return expandAll || expandedCheck === checkId
  }

  if (checks.length === 0) {
    return null
  }

  return (
    <div className="rounded-xl border bg-card p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-base font-semibold flex items-center gap-2">
          <svg
            className="h-5 w-5 text-primary"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"
            />
          </svg>
          Checks
          <span className="ml-2 text-xs text-muted-foreground font-normal px-2 py-0.5 bg-muted rounded-full">
            {filteredChecks.length} / {checks.length}
          </span>
        </h3>
        <Button
          variant="outline"
          size="sm"
          onClick={() => setExpandAll(!expandAll)}
          className="gap-1.5"
        >
          <ChevronsUpDown className="h-4 w-4" />
          {expandAll ? "Collapse All" : "Expand All"}
        </Button>
      </div>

      {/* Filters */}
      <div className="flex gap-3 mb-4 flex-col sm:flex-row">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
          <input
            type="text"
            placeholder="Search check ID, title, description..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 h-9 text-sm rounded-lg border border-input bg-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50"
          />
        </div>
        <div className="flex gap-1 flex-wrap">
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

      {/* Checks List */}
      <div className="space-y-4 max-h-[500px] overflow-y-auto scrollbar-thin pr-1">
        {Object.entries(checksBySeverity).map(([severity, checkList]) => {
          if (checkList.length === 0) return null

          return (
            <div key={severity} className="space-y-2">
              <div
                className={`flex items-center justify-between px-3 py-2 rounded-lg ${getSeverityBgColor(severity)}`}
              >
                <span className={`text-sm font-semibold ${getSeverityColor(severity)}`}>
                  {severity} ({checkList.length})
                </span>
              </div>
              <div className="space-y-2">
                {checkList.map((check, index) => {
                  const checkID = check.checkID || check.id || `Check-${severity}-${index}`
                  const expanded = isExpanded(checkID)

                  return (
                    <div
                      key={checkID}
                      className={`border rounded-lg p-4 text-left ${getSeverityBgColor(check.severity || "unknown")} cursor-pointer hover:shadow-md transition-all duration-200`}
                      onClick={() => handleToggle(checkID)}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex-1 min-w-0 text-left">
                          <div className="flex items-center gap-2 mb-2 flex-wrap">
                            <span className="font-bold text-sm text-foreground">{checkID}</span>
                            {check.severity && (
                              <span
                                className={`text-xs font-semibold px-2 py-0.5 rounded-full ${getSeverityBadgeColor(check.severity)}`}
                              >
                                {check.severity.toUpperCase()}
                              </span>
                            )}
                          </div>
                          {check.title && (
                            <div className="text-sm font-medium text-foreground mb-2 line-clamp-2 text-left">
                              {check.title}
                            </div>
                          )}
                          {check.category && (
                            <div className="text-xs text-muted-foreground text-left">
                              Category: <span className="font-medium">{check.category}</span>
                            </div>
                          )}
                        </div>
                        <button className="ml-2 flex-shrink-0 p-1 rounded hover:bg-black/5 dark:hover:bg-white/5">
                          {expanded ? (
                            <ChevronUp className="h-4 w-4 text-muted-foreground" />
                          ) : (
                            <ChevronDown className="h-4 w-4 text-muted-foreground" />
                          )}
                        </button>
                      </div>

                      {expanded && (
                        <div className="mt-4 pt-4 border-t space-y-4 text-left">
                          {check.description && (
                            <div className="text-sm text-foreground leading-relaxed text-left">
                              {check.description}
                            </div>
                          )}
                          {check.remediation && (
                            <div className="text-left">
                              <div className="text-sm font-semibold text-foreground mb-2 text-left">
                                Remediation:
                              </div>
                              <div className="p-3 bg-muted rounded-lg text-sm text-foreground leading-relaxed text-left">
                                {check.remediation}
                              </div>
                            </div>
                          )}
                          {check.success !== undefined && (
                            <div className="text-sm text-muted-foreground text-left">
                              <span className="font-semibold">Success: </span>
                              <span
                                className={
                                  check.success
                                    ? "text-green-600 dark:text-green-400"
                                    : "text-red-600 dark:text-red-400"
                                }
                              >
                                {check.success ? "Yes" : "No"}
                              </span>
                            </div>
                          )}
                          {check.messages &&
                            Array.isArray(check.messages) &&
                            check.messages.length > 0 && (
                              <div className="text-left">
                                <div className="text-sm font-semibold text-foreground mb-2 text-left">
                                  Messages:
                                </div>
                                <div className="space-y-2">
                                  {check.messages.map((msg, msgIndex) => (
                                    <div
                                      key={msgIndex}
                                      className="text-sm text-muted-foreground pl-3 border-l-2 border-primary/30 leading-relaxed text-left"
                                    >
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
  )
}
