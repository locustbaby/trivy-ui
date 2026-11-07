import { useEffect, useState } from "react"
import { Loader2, RefreshCw, X } from "lucide-react"
import { api, ApiError } from "../api/client"
import { Button } from "./ui/button"
import { toast } from "../lib/toast"
import { formatReportTypeName } from "../lib/utils"

interface BulkRescanPanelProps {
  cluster: string
  typeName: string
  namespaces: string[]
  maxBulk: number
  onClose: () => void
  onRequested: () => void
}

const AGE_OPTIONS = [
  { value: "", label: "Any age" },
  { value: "6h", label: "Older than 6 hours" },
  { value: "12h", label: "Older than 12 hours" },
  { value: "24h", label: "Older than 24 hours" },
  { value: "72h", label: "Older than 3 days" },
]

// Rescans every report of the current type and namespace filter. A dry run
// shows how many reports match before anything is deleted.
export function BulkRescanPanel({ cluster, typeName, namespaces, maxBulk, onClose, onRequested }: BulkRescanPanelProps) {
  const [olderThan, setOlderThan] = useState("")
  const [count, setCount] = useState<number | null>(null)
  const [checking, setChecking] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string>()

  useEffect(() => {
    let active = true
    void Promise.resolve().then(() => {
      if (!active) return
      setChecking(true)
      setError(undefined)
      api.rescanBulk({ cluster, types: [typeName], namespaces, olderThan: olderThan || undefined, dryRun: true })
        .then((result) => active && setCount(result.count))
        .catch((err) => active && setError(err instanceof Error ? err.message : "Could not count matching reports"))
        .finally(() => active && setChecking(false))
    })
    return () => {
      active = false
    }
  }, [cluster, typeName, namespaces, olderThan])

  const submit = () => {
    setSubmitting(true)
    api.rescanBulk({ cluster, types: [typeName], namespaces, olderThan: olderThan || undefined })
      .then((result) => {
        const failed = result.failed?.length ?? 0
        toast(
          failed > 0
            ? `Rescan requested for ${result.accepted ?? 0} reports; ${failed} could not be requested.`
            : `Rescan requested for ${result.accepted ?? 0} reports. They are scanned one after another.`,
          failed > 0 ? "error" : "info",
        )
        onRequested()
        onClose()
      })
      .catch((err) => {
        const message = err instanceof ApiError || err instanceof Error ? err.message : "Rescan failed"
        setError(message)
      })
      .finally(() => setSubmitting(false))
  }

  const scope = namespaces.length > 0 ? `namespace${namespaces.length > 1 ? "s" : ""} ${namespaces.join(", ")}` : "all namespaces"
  const tooMany = count !== null && count > maxBulk

  return (
    <div role="dialog" aria-label="Rescan reports" className="rounded-xl border border-sky-500/30 bg-sky-500/5 p-4 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold">Rescan {formatReportTypeName(typeName)}</h3>
          <p className="text-xs text-muted-foreground">
            Cluster {cluster}, {scope}. The Trivy Operator scans the workloads again one after another; current results stay visible until each new scan is done.
          </p>
        </div>
        <button onClick={onClose} className="p-1 rounded hover:bg-muted text-muted-foreground" aria-label="Close rescan panel">
          <X className="h-4 w-4" />
        </button>
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <label className="text-sm text-muted-foreground" htmlFor="rescan-age">Reports</label>
        <select
          id="rescan-age"
          className="h-9 rounded-lg border bg-background px-2 text-sm"
          value={olderThan}
          onChange={(e) => setOlderThan(e.target.value)}
          disabled={submitting}
        >
          {AGE_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
        </select>
        <span className="text-sm" aria-live="polite">
          {checking ? (
            <span className="inline-flex items-center gap-1.5 text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" />Counting…</span>
          ) : count !== null && (
            <span className={tooMany ? "text-destructive" : ""}>
              {count} report{count === 1 ? "" : "s"} match{count === 1 ? "es" : ""}{tooMany ? ` — at most ${maxBulk} at once, narrow the selection` : ""}
            </span>
          )}
        </span>
      </div>
      {error && <p className="text-sm text-destructive">{error}</p>}
      <div className="flex gap-2">
        <Button size="sm" className="gap-1.5" onClick={submit} disabled={checking || submitting || !count || tooMany}>
          {submitting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
          Rescan {count ?? ""} report{count === 1 ? "" : "s"}
        </Button>
        <Button size="sm" variant="ghost" onClick={onClose} disabled={submitting}>Cancel</Button>
      </div>
    </div>
  )
}
