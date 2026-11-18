import { useEffect, useMemo, useState } from "react"
import { ChevronDown, ChevronRight, Download, ExternalLink, Loader2, Search, ShieldCheck, Wrench } from "lucide-react"
import { api, type ReportRef, type VulnerabilityEntry, type VulnerabilityList } from "../api/client"
import { Button } from "./ui/button"
import { useDebounce } from "../hooks/useDebounce"
import { getSeverityBadgeColor } from "../lib/severity"
import { advisoryLinks } from "../lib/advisory"
import { downloadCSV, downloadJSON, exportFilename } from "../lib/export"
import { cn } from "../lib/utils"

interface CveViewProps {
  cluster?: string
  namespace?: string
  onOpenReport: (ref: ReportRef) => void
}

const SEVERITIES = ["critical", "high", "medium", "low", "unknown"] as const
const PAGE = 100

// Every distinct vulnerability in the selected scope, with the workloads,
// images and packages it affects.
export function CveView({ cluster, namespace, onOpenReport }: CveViewProps) {
  const [search, setSearch] = useState("")
  const [severity, setSeverity] = useState<string>("")
  const [fixableOnly, setFixableOnly] = useState(false)
  const [data, setData] = useState<VulnerabilityList | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>()
  const [expanded, setExpanded] = useState<string | null>(null)
  const [visible, setVisible] = useState(PAGE)
  const debouncedSearch = useDebounce(search, 300)

  useEffect(() => {
    const controller = new AbortController()
    void Promise.resolve().then(() => {
      setLoading(true)
      setError(undefined)
      setVisible(PAGE)
      api.getVulnerabilities({ cluster, namespace, search: debouncedSearch, severity, fixable: fixableOnly }, controller.signal)
        .then(setData)
        .catch((err) => {
          if (!(err instanceof Error && err.name === "AbortError")) setError(err instanceof Error ? err.message : "Failed to load vulnerabilities")
        })
        .finally(() => setLoading(false))
    })
    return () => controller.abort()
  }, [cluster, namespace, debouncedSearch, severity, fixableOnly])

  const items = useMemo(() => data?.items ?? [], [data])

  const exportRows = () =>
    items.flatMap((item) =>
      item.occurrences.map((o) => ({
        id: item.id, severity: item.severity, title: item.title, cluster: o.cluster, namespace: o.namespace,
        workload: o.workload, workload_kind: o.workload_kind, image: o.image, package: o.package,
        installed: o.installed, fixed: o.fixed, report: o.report,
      })),
    )

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold">Vulnerabilities</h2>
          <p className="text-sm text-muted-foreground">
            Each vulnerability once, with the workloads and images it affects{namespace ? ` in ${namespace}` : ""}.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" className="gap-1.5" disabled={!items.length}
            onClick={() => downloadCSV(exportRows(), ["id", "severity", "title", "cluster", "namespace", "workload", "workload_kind", "image", "package", "installed", "fixed", "report"], exportFilename("vulnerabilities", "csv"))}>
            <Download className="h-4 w-4" />CSV
          </Button>
          <Button variant="outline" size="sm" className="gap-1.5" disabled={!items.length}
            onClick={() => downloadJSON(items, exportFilename("vulnerabilities", "json"))}>
            <Download className="h-4 w-4" />JSON
          </Button>
        </div>
      </div>

      <div className="flex flex-col lg:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" aria-hidden="true" />
          <input
            type="search"
            aria-label="Search vulnerabilities"
            className="w-full pl-10 pr-3 py-2.5 rounded-xl border bg-background text-sm outline-none focus:ring-2 focus:ring-primary/50"
            placeholder="CVE ID, title, package, workload or image…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="flex flex-wrap gap-1" role="group" aria-label="Severity">
          {["", ...SEVERITIES].map((sev) => (
            <Button key={sev || "all"} size="sm" variant={severity === sev ? "default" : "outline"} className="h-10 text-xs capitalize"
              aria-pressed={severity === sev} onClick={() => setSeverity(sev)}>
              {sev || "All"}
            </Button>
          ))}
          <Button size="sm" variant={fixableOnly ? "default" : "outline"} className="h-10 text-xs gap-1.5" aria-pressed={fixableOnly}
            onClick={() => setFixableOnly((value) => !value)}>
            <Wrench className="h-3.5 w-3.5" />Fixable only
          </Button>
        </div>
      </div>

      <p className="text-sm text-muted-foreground" aria-live="polite">
        {loading ? "Loading…" : data ? `${data.total.toLocaleString()} vulnerabilities${data.truncated ? ` (first ${items.length} shown, narrow the filter)` : ""}` : ""}
      </p>

      {error && <p className="text-sm text-destructive">{error}</p>}
      {data && !data.indexed && (
        <p className="text-sm text-muted-foreground">The CVE index is turned off on this server (CVE_INDEX=false).</p>
      )}
      {loading && !data && (
        <div className="flex justify-center py-12"><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></div>
      )}
      {data && items.length === 0 && !loading && (
        <div className="flex flex-col items-center py-12 rounded-2xl border bg-card/50 text-muted-foreground">
          <ShieldCheck className="h-10 w-10 text-green-500 mb-2" />
          No vulnerabilities match
        </div>
      )}

      <ul className="space-y-2">
        {items.slice(0, visible).map((item) => (
          <CveRow key={item.id} item={item} open={expanded === item.id}
            onToggle={() => setExpanded((current) => (current === item.id ? null : item.id))} onOpenReport={onOpenReport} />
        ))}
      </ul>
      {items.length > visible && (
        <div className="flex justify-center">
          <Button variant="outline" size="sm" onClick={() => setVisible((count) => count + PAGE)}>
            Show {Math.min(PAGE, items.length - visible)} more
          </Button>
        </div>
      )}
    </div>
  )
}

function CveRow({ item, open, onToggle, onOpenReport }: { item: VulnerabilityEntry; open: boolean; onToggle: () => void; onOpenReport: (ref: ReportRef) => void }) {
  const panelId = `cve-${item.id}`
  return (
    <li className="rounded-xl border bg-card">
      <button onClick={onToggle} aria-expanded={open} aria-controls={panelId}
        className="w-full text-left p-3 flex items-start gap-3 hover:bg-muted/40 rounded-xl focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50">
        {open ? <ChevronDown className="h-4 w-4 mt-0.5 flex-shrink-0" /> : <ChevronRight className="h-4 w-4 mt-0.5 flex-shrink-0" />}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className={cn("text-[10px] font-bold uppercase px-1.5 py-0.5 rounded", getSeverityBadgeColor(item.severity))}>{item.severity}</span>
            <span className="font-mono text-sm font-semibold">{item.id}</span>
            {item.fixable
              ? <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-green-500/10 text-green-700 dark:text-green-400">fix available</span>
              : <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-muted text-muted-foreground">no fix yet</span>}
          </div>
          {item.title && <p className="text-sm text-muted-foreground truncate mt-0.5">{item.title}</p>}
          <p className="text-xs text-muted-foreground mt-0.5">
            {item.workloads} workload{item.workloads === 1 ? "" : "s"} · {item.images} image{item.images === 1 ? "" : "s"} · {item.packages.join(", ")}
          </p>
        </div>
      </button>
      {open && (
        <div id={panelId} role="region" aria-label={`${item.id} details`} className="border-t px-3 pb-3 pt-2 space-y-2">
          <div className="flex flex-wrap gap-3 text-xs">
            {advisoryLinks(item.id).map((link) => (
              <a key={link.url} href={link.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-primary hover:underline">
                <ExternalLink className="h-3 w-3" />{link.label}
              </a>
            ))}
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="text-muted-foreground text-left">
                <tr><th className="py-1 pr-3 font-medium">Workload</th><th className="py-1 pr-3 font-medium">Image</th><th className="py-1 pr-3 font-medium">Package</th><th className="py-1 font-medium">Upgrade</th></tr>
              </thead>
              <tbody>
                {item.occurrences.map((o, index) => (
                  <tr key={`${o.report}-${o.package}-${index}`} className="border-t">
                    <td className="py-1.5 pr-3">
                      <button className="text-left hover:underline text-primary" onClick={() => onOpenReport({ cluster: o.cluster, namespace: o.namespace, type: o.report_type, name: o.report })}>
                        {o.namespace}/{o.workload}
                      </button>
                    </td>
                    <td className="py-1.5 pr-3 font-mono break-all">{o.image}</td>
                    <td className="py-1.5 pr-3 font-mono">{o.package}</td>
                    <td className="py-1.5 font-mono whitespace-nowrap">
                      {o.installed} {o.fixed ? <>→ <span className="text-green-700 dark:text-green-400">{o.fixed}</span></> : <span className="text-muted-foreground">(no fix)</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </li>
  )
}
