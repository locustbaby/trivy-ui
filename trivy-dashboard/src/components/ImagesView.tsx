import { useEffect, useState } from "react"
import { Download, Loader2, Search, ShieldCheck } from "lucide-react"
import { api, type ImageEntry, type ReportRef } from "../api/client"
import { Button } from "./ui/button"
import { useDebounce } from "../hooks/useDebounce"
import { downloadCSV, exportFilename } from "../lib/export"
import { scanAge } from "../lib/utils"

interface ImagesViewProps {
  cluster?: string
  namespace?: string
  onOpenReport: (ref: ReportRef) => void
}

const PILLS = [
  { key: "critical", label: "CRIT", className: "bg-red-100 dark:bg-red-950/50 text-red-700 dark:text-red-400" },
  { key: "high", label: "HIGH", className: "bg-orange-100 dark:bg-orange-950/50 text-orange-700 dark:text-orange-400" },
  { key: "medium", label: "MED", className: "bg-yellow-100 dark:bg-yellow-950/50 text-yellow-700 dark:text-yellow-400" },
  { key: "low", label: "LOW", className: "bg-blue-100 dark:bg-blue-950/50 text-blue-700 dark:text-blue-400" },
  { key: "unknown", label: "UNK", className: "bg-slate-100 dark:bg-slate-800/60 text-slate-600 dark:text-slate-300" },
] as const

// Each image once, however many workloads run it: which image to rebuild.
export function ImagesView({ cluster, namespace, onOpenReport }: ImagesViewProps) {
  const [search, setSearch] = useState("")
  const [items, setItems] = useState<ImageEntry[] | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>()
  const debouncedSearch = useDebounce(search, 300)

  useEffect(() => {
    const controller = new AbortController()
    void Promise.resolve().then(() => {
      setLoading(true)
      setError(undefined)
      api.getImages({ cluster, namespace, search: debouncedSearch }, controller.signal)
        .then((data) => setItems(data.items))
        .catch((err) => {
          if (!(err instanceof Error && err.name === "AbortError")) setError(err instanceof Error ? err.message : "Failed to load images")
        })
        .finally(() => setLoading(false))
    })
    return () => controller.abort()
  }, [cluster, namespace, debouncedSearch])

  const exportCSV = () => downloadCSV(
    (items ?? []).map((item) => ({
      image: item.image, digest: item.digest, critical: item.critical, high: item.high, medium: item.medium, low: item.low,
      unknown: item.unknown, fixable_critical: item.fixable_critical, fixable_high: item.fixable_high,
      workloads: item.workloads.map((w) => `${w.namespace}/${w.name}`).join(" "), scanned_at: item.scanned_at,
    })),
    ["image", "digest", "critical", "high", "medium", "low", "unknown", "fixable_critical", "fixable_high", "workloads", "scanned_at"],
    exportFilename("images", "csv"),
  )

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold">Images</h2>
          <p className="text-sm text-muted-foreground">Vulnerabilities per container image, once per image however many workloads run it.</p>
        </div>
        <Button variant="outline" size="sm" className="gap-1.5" disabled={!items?.length} onClick={exportCSV}>
          <Download className="h-4 w-4" />CSV
        </Button>
      </div>
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" aria-hidden="true" />
        <input
          type="search"
          aria-label="Search images"
          className="w-full pl-10 pr-3 py-2.5 rounded-xl border bg-background text-sm outline-none focus:ring-2 focus:ring-primary/50"
          placeholder="Image, workload or namespace…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>
      <p className="text-sm text-muted-foreground" aria-live="polite">
        {loading ? "Loading…" : items ? `${items.length} images` : ""}
      </p>
      {error && <p className="text-sm text-destructive">{error}</p>}
      {loading && !items && <div className="flex justify-center py-12"><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></div>}
      {items && items.length === 0 && !loading && (
        <div className="flex flex-col items-center py-12 rounded-2xl border bg-card/50 text-muted-foreground">
          <ShieldCheck className="h-10 w-10 text-green-500 mb-2" />No images match
        </div>
      )}
      <ul className="space-y-2">
        {(items ?? []).map((item) => {
          const fixable = item.fixable_critical + item.fixable_high
          const age = scanAge(item.scanned_at)
          return (
            <li key={`${item.image}@${item.digest ?? ""}`} className="rounded-xl border bg-card p-3 space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-sm font-semibold break-all">{item.image}</span>
                {item.digest && <span className="font-mono text-[10px] text-muted-foreground" title={item.digest}>{item.digest.slice(0, 19)}</span>}
              </div>
              <div className="flex flex-wrap items-center gap-1.5">
                {PILLS.map((pill) => item[pill.key] > 0 && (
                  <span key={pill.key} className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full text-xs font-medium ${pill.className}`}>
                    {item[pill.key]} <span className="text-[9px] font-bold opacity-75">{pill.label}</span>
                  </span>
                ))}
                {fixable > 0 && <span className="text-xs text-muted-foreground">{fixable} Critical/High fixable</span>}
                {age && <span className={`text-xs ${age.stale ? "text-amber-600 dark:text-amber-400" : "text-muted-foreground"}`}>scanned {age.label}</span>}
              </div>
              <div className="flex flex-wrap gap-1.5">
                {item.workloads.map((workload) => (
                  <button
                    key={`${workload.namespace}/${workload.name}`}
                    className="text-xs px-2 py-1 rounded-lg border bg-background hover:bg-muted"
                    onClick={() => onOpenReport(workload.report)}
                    title={workload.kind ? `${workload.kind} ${workload.namespace}/${workload.name}` : undefined}
                  >
                    {workload.namespace}/{workload.name}
                  </button>
                ))}
              </div>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
