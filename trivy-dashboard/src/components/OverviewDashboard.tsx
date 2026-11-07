import * as React from "react"
import { useEffect, useMemo, useRef, useState } from "react"
import { api } from "../api/client"
import type { ClusterOverview, TrendRecord, WorkloadSummary } from "../api/client"
import {
  Shield,
  AlertTriangle,
  AlertCircle,
  Info,
  ShieldCheck,
  Loader2,
  X,
  Bug,
  ClipboardCheck,
  KeyRound,
  Cpu,
  Users,
  Boxes,
  Layers,
  ChevronRight,
  HelpCircle,
} from "lucide-react"
import { Button } from "./ui/button"
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts"
import { cn, reportTypeLabel } from "../lib/utils"
import { formatTrendLabel, vulnerabilityTrend } from "../lib/trends"

interface OverviewDashboardProps {
  selectedCluster?: string
  onSelectNamespace: (ns: string) => void
  onSelectWorkload: (w: WorkloadSummary) => void
  onSelectCluster: (cluster: string) => void
  onSelectType?: (type: string) => void
  onSelectView?: (view: string) => void
  onShowStale?: () => void
}

function getBreakdownIcon(type: string) {
  const lower = type.toLowerCase()
  if (lower.includes("vulnerab")) return Bug
  if (lower.includes("config")) return ClipboardCheck
  if (lower.includes("secret")) return KeyRound
  if (lower.includes("infra")) return Cpu
  if (lower.includes("rbac")) return Users
  if (lower.includes("sbom")) return Boxes
  if (lower.includes("complian")) return ShieldCheck
  return Layers
}

const TREND_RANGES = [7, 30, 90] as const

const SEVERITY_TILES = [
  { key: "critical", label: "Critical", icon: Shield, color: "text-red-500", bg: "bg-red-500/10 border-red-500/20" },
  { key: "high", label: "High", icon: AlertTriangle, color: "text-orange-500", bg: "bg-orange-500/10 border-orange-500/20" },
  { key: "medium", label: "Medium", icon: AlertCircle, color: "text-yellow-500", bg: "bg-yellow-500/10 border-yellow-500/20" },
  { key: "low", label: "Low", icon: Info, color: "text-blue-500", bg: "bg-blue-500/10 border-blue-500/20" },
  { key: "unknown", label: "Unknown", icon: HelpCircle, color: "text-slate-500", bg: "bg-slate-500/10 border-slate-500/20" },
] as const

// Downsample hourly points: hourly for a week, one point per day beyond.
function trendPoints(records: TrendRecord[], days: number) {
  const points = days <= 7 ? records : Object.values(
    records.reduce<Record<string, TrendRecord>>((byDay, record) => {
      byDay[new Date(record.timestamp).toDateString()] = record
      return byDay
    }, {}),
  )
  return points.map((t) => ({
    name: formatTrendLabel(t.timestamp, days),
    critical: t.critical,
    high: t.high,
    medium: t.medium,
    fixable: t.kind ? (t.fixable_critical ?? 0) + (t.fixable_high ?? 0) : undefined,
  }))
}

function namespaceLabel(name: string) {
  return name && name !== "_" ? name : "Cluster-scoped"
}

function OverviewDashboardInternal({ selectedCluster, onSelectNamespace, onSelectWorkload, onSelectCluster, onSelectType, onSelectView, onShowStale }: OverviewDashboardProps) {
  const [data, setData] = useState<ClusterOverview | null>(null)
  const [trends, setTrends] = useState<TrendRecord[]>([])
  const [days, setDays] = useState<number>(30)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>()
  const [retryCount, setRetryCount] = useState(0)
  const generationRef = useRef(0)
  const loadedClusterRef = useRef<string | undefined>(undefined)

  useEffect(() => {
    const generation = ++generationRef.current
    const controller = new AbortController()
    setError(undefined)
    // Keep the view while only the trend range changes; clear it when the
    // cluster changes so no numbers of the previous cluster are shown.
    if (loadedClusterRef.current !== selectedCluster) {
      setData(null)
      setTrends([])
    }
    const load = async () => {
      setLoading(true)
      try {
        const [ovData, trData] = await Promise.all([
          api.getOverview(selectedCluster, controller.signal),
          api.getOverviewTrends(selectedCluster, days, controller.signal)
        ])
        if (generation === generationRef.current) {
          loadedClusterRef.current = selectedCluster
          setData(ovData)
          setTrends(trData.filter((t) => !t.namespace && (selectedCluster ? t.cluster === selectedCluster : t.cluster === "")))
        }
      } catch (e) {
        if (e instanceof Error && e.name === "AbortError") return
        if (generation === generationRef.current) {
          setError(e instanceof Error ? e.message : "Failed to load overview")
        }
      } finally {
        if (generation === generationRef.current) setLoading(false)
      }
    }
    load()
    return () => controller.abort()
  }, [selectedCluster, retryCount, days])

  const trend = useMemo(() => vulnerabilityTrend(trends), [trends])
  const chartData = useMemo(() => trendPoints(trend.records, days), [trend, days])

	if (loading && !data) {
		return (
			<div className="flex h-[60vh] items-center justify-center">
				<Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
			</div>
		)
	}

	if (error && !data) {
		return (
			<div className="flex flex-col items-center justify-center py-16 rounded-2xl border bg-card/50">
				<X className="h-12 w-12 text-destructive mb-3" />
				<div className="mb-4 text-destructive font-medium">{error}</div>
				<Button onClick={() => setRetryCount((count) => count + 1)} size="sm">Retry</Button>
			</div>
		)
	}

	if (!data) return null

  const families = data.families
  const vulns = families?.vulnerabilities
  const otherFamilies = families ? [
    { key: "misconfigurations", label: "Misconfigurations", hint: "Config & infra checks", icon: ClipboardCheck, totals: families.misconfigurations, type: "configauditreports" },
    { key: "rbac", label: "RBAC", hint: "Risky roles & bindings", icon: Users, totals: families.rbac, type: "rbacassessmentreports" },
    { key: "secrets", label: "Exposed secrets", hint: "Secrets in images", icon: KeyRound, totals: families.secrets, type: "exposedsecretreports" },
  ] : []

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500 ease-out">
      {vulns ? (
        <section aria-labelledby="vulnerability-totals" className="space-y-3">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h2 id="vulnerability-totals" className="text-base font-semibold">Vulnerabilities in container images</h2>
            <div className="flex flex-wrap items-baseline gap-3 text-xs">
              <button onClick={() => onSelectType?.("vulnerabilityreports")} className="text-muted-foreground hover:text-foreground">
                {vulns.with_findings.toLocaleString()} of {vulns.reports.toLocaleString()} images affected
                {(data.retired_reports ?? 0) > 0 && ` · ${data.retired_reports} reports of retired ReplicaSets not counted`}
              </button>
              {onSelectView && (
                <>
                  <button onClick={() => onSelectView("cves")} className="font-medium text-primary hover:underline">By CVE →</button>
                  <button onClick={() => onSelectView("images")} className="font-medium text-primary hover:underline">By image →</button>
                </>
              )}
            </div>
          </div>
          {(data.stale_reports ?? 0) > 0 && (
            <div role="status" className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-700 dark:text-amber-300">
              <span>
                {data.stale_reports} report{data.stale_reports === 1 ? " was" : "s were"} not rescanned for more than {data.stale_after_hours ?? 72} hours — check that the Trivy Operator is scanning.
              </span>
              {onShowStale && <button onClick={onShowStale} className="font-medium underline">Show oldest scans</button>}
            </div>
          )}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
            {SEVERITY_TILES.map((sev) => {
              const count = vulns[sev.key]
              const fixableCount = vulns[`fixable_${sev.key}` as const]
              return (
                <div key={sev.key} className={`p-4 rounded-2xl border ${sev.bg} flex items-start justify-between shadow-xs`}>
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">{sev.label}</p>
                    <p className={`text-3xl font-bold mt-1 tracking-tight ${sev.color}`}>{count.toLocaleString()}</p>
                    <p className="text-xs text-muted-foreground mt-0.5" title="Findings with a fixed version available">
                      {fixableCount.toLocaleString()} fixable
                    </p>
                  </div>
                  <sev.icon className={`h-5 w-5 ${sev.color}`} aria-hidden="true" />
                </div>
              )
            })}
          </div>
        </section>
      ) : (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {SEVERITY_TILES.slice(0, 4).map((sev) => (
            <div key={sev.key} className={`p-4 rounded-2xl border ${sev.bg} shadow-xs`}>
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">{sev.label}</p>
              <p className={`text-3xl font-bold mt-1 tracking-tight ${sev.color}`}>{(data.severity_totals[sev.key as "critical"] ?? 0).toLocaleString()}</p>
            </div>
          ))}
        </div>
      )}

      {families && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {otherFamilies.map((family) => (
            <button
              key={family.key}
              onClick={() => onSelectType?.(family.type)}
              className="text-left p-4 rounded-2xl border bg-card hover:bg-muted/40 transition-colors"
            >
              <div className="flex items-center gap-2 text-sm font-semibold">
                <family.icon className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
                {family.label}
              </div>
              <p className="text-xs text-muted-foreground">{family.hint}</p>
              <div className="mt-2 flex flex-wrap items-center gap-1.5 text-xs">
                {family.key === "secrets" ? (
                  <span className={cn("px-2 py-0.5 rounded font-medium", family.totals.with_findings > 0 ? "bg-red-500/10 text-red-500" : "bg-green-500/10 text-green-600 dark:text-green-400")}>
                    {family.totals.with_findings > 0 ? `${family.totals.with_findings} images with secrets` : "None found"}
                  </span>
                ) : (
                  <>
                    <span className="px-2 py-0.5 rounded bg-red-500/10 text-red-500 font-medium">{family.totals.critical} Crit</span>
                    <span className="px-2 py-0.5 rounded bg-orange-500/10 text-orange-500 font-medium">{family.totals.high} High</span>
                    <span className="text-muted-foreground">{family.totals.with_findings}/{family.totals.reports} with findings</span>
                  </>
                )}
              </div>
            </button>
          ))}
          <button
            onClick={() => onSelectType?.("clustercompliancereports")}
            className="text-left p-4 rounded-2xl border bg-card hover:bg-muted/40 transition-colors"
          >
            <div className="flex items-center gap-2 text-sm font-semibold">
              <ShieldCheck className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
              Compliance
            </div>
            <p className="text-xs text-muted-foreground">{families.compliance.reports} frameworks</p>
            <div className="mt-2 flex flex-wrap items-center gap-1.5 text-xs">
              <span className="px-2 py-0.5 rounded bg-green-500/10 text-green-600 dark:text-green-400 font-medium">{families.compliance.pass} pass</span>
              <span className="px-2 py-0.5 rounded bg-red-500/10 text-red-500 font-medium">{families.compliance.fail} fail</span>
            </div>
          </button>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-stretch">
        {/* Trend Chart */}
        <div className="lg:col-span-2 rounded-2xl border bg-card p-5 shadow-sm flex flex-col justify-between">
          <div className="flex flex-wrap items-start justify-between gap-2 mb-4">
            <div>
              <h3 className="text-base font-semibold">Vulnerability trend</h3>
              <p className="text-xs text-muted-foreground">
                {trend.legacy
                  ? "Older data: all report types added up"
                  : "Critical, High and Medium findings; dashed: Critical + High with a fix"}
              </p>
            </div>
            <div className="flex gap-1" role="group" aria-label="Trend range">
              {TREND_RANGES.map((range) => (
                <Button
                  key={range}
                  size="sm"
                  variant={days === range ? "default" : "outline"}
                  className="h-7 px-2.5 text-xs"
                  aria-pressed={days === range}
                  onClick={() => setDays(range)}
                >
                  {range}d
                </Button>
              ))}
            </div>
          </div>
          <div className="h-[320px] w-full flex-1 min-h-[260px] min-w-0">
            <ResponsiveContainer width="100%" height="100%" minWidth={0}>
              <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f97316" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#f97316" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorMedium" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#eab308" stopOpacity={0.15}/>
                    <stop offset="95%" stopColor="#eab308" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="currentColor" className="text-muted-foreground/20" />
                <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fontSize: 12 }} stroke="currentColor" className="text-muted-foreground" minTickGap={24} />
                <YAxis axisLine={false} tickLine={false} tick={{ fontSize: 12 }} stroke="currentColor" className="text-muted-foreground" />
                <Tooltip contentStyle={{ backgroundColor: 'hsl(var(--card))', borderColor: 'hsl(var(--border))', borderRadius: '8px' }} />
                <Area type="monotone" dataKey="medium" name="Medium" stroke="#eab308" fillOpacity={1} fill="url(#colorMedium)" strokeWidth={1.5} />
                <Area type="monotone" dataKey="high" name="High" stroke="#f97316" fillOpacity={1} fill="url(#colorHigh)" strokeWidth={2} />
                <Area type="monotone" dataKey="critical" name="Critical" stroke="#ef4444" fillOpacity={1} fill="url(#colorCritical)" strokeWidth={2} />
                {!trend.legacy && (
                  <Area type="monotone" dataKey="fixable" name="Fixable (Crit + High)" stroke="#22c55e" strokeDasharray="5 4" fill="none" strokeWidth={2} />
                )}
              </AreaChart>
            </ResponsiveContainer>
          </div>
          {trend.hiddenBefore && (
            <p className="mt-2 text-[11px] text-muted-foreground">
              Data before {trend.hiddenBefore.toLocaleDateString()} added up all report types and is not shown.
            </p>
          )}
        </div>

        {/* Scan Category Matrix */}
        <div className="rounded-2xl border bg-card p-5 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-base font-semibold">Scan Breakdown</h3>
            <span className="text-xs text-muted-foreground font-medium">{Object.keys(data.scan_types_breakdown).length} types</span>
          </div>
          <div className="space-y-3 flex-1 overflow-y-auto max-h-[320px] pr-1.5 scrollbar-thin">
            {Object.entries(data.scan_types_breakdown).map(([type, stats]) => {
              const withFindings = stats.with_findings ?? stats.failed
              const passRate = stats.scanned > 0 ? Math.round(((stats.scanned - withFindings) / stats.scanned) * 100) : 100
              const isHealthy = passRate > 80
              const Icon = getBreakdownIcon(type)
              const formattedName = reportTypeLabel(type)
              return (
                <div key={type} className="p-2.5 rounded-xl border bg-background/50 hover:bg-muted/40 transition-colors">
                  <div className="flex items-center justify-between text-xs mb-1.5">
                    <div className="flex items-center gap-2 min-w-0">
                      <Icon className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />
                      <span className="font-semibold truncate" title={formattedName}>{formattedName}</span>
                    </div>
                    <span className={cn("font-semibold text-[11px] whitespace-nowrap px-1.5 py-0.2 rounded", isHealthy ? "text-green-600 bg-green-500/10 dark:text-green-400" : "text-amber-600 bg-amber-500/10 dark:text-amber-400")}>
                      {passRate}% clean
                    </span>
                  </div>
                  <div className="h-1.5 w-full bg-muted rounded-full overflow-hidden">
                    <div 
                      className={`h-full rounded-full transition-all ${isHealthy ? 'bg-green-500' : 'bg-orange-500'}`} 
                      style={{ width: `${passRate}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-[10px] mt-1 text-muted-foreground">
                    <span>{stats.scanned.toLocaleString()} Scanned</span>
                    <span>{withFindings > 0 ? `${withFindings.toLocaleString()} with findings` : "No findings"}</span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-stretch">
        {/* Top Vulnerable Workloads */}
        <div className="rounded-2xl border bg-card p-5 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-semibold">Top Vulnerable Workloads</h3>
            <span className="text-xs text-muted-foreground">{data.top_vulnerable_workloads.length} items</span>
          </div>
          <div className="space-y-2 flex-1 overflow-y-auto max-h-[300px] pr-1 scrollbar-thin">
            {data.top_vulnerable_workloads.map((w) => (
              <button 
                key={JSON.stringify([w.cluster, w.namespace, w.kind, w.name])}
                onClick={() => onSelectWorkload(w)}
                className="w-full text-left p-3 rounded-xl hover:bg-muted/50 border bg-background/40 transition-colors flex items-center justify-between group"
              >
                <div className="overflow-hidden mr-3">
                  <p className="font-semibold text-sm truncate">{w.name}</p>
                  <p className="text-xs text-muted-foreground truncate">
                    {namespaceLabel(w.namespace)}{w.kind ? ` • ${w.kind}` : ""}{(w.reports?.length ?? 0) > 1 ? ` • ${w.reports!.length} containers` : ""}
                  </p>
                </div>
                <div className="flex items-center gap-1.5 flex-shrink-0">
                  {w.critical > 0 && <span className="text-xs px-2 py-0.5 rounded bg-red-500/10 text-red-500 font-medium">{w.critical} Crit</span>}
                  {w.high > 0 && <span className="text-xs px-2 py-0.5 rounded bg-orange-500/10 text-orange-500 font-medium">{w.high} High</span>}
                  {(w.fixable_critical ?? 0) + (w.fixable_high ?? 0) > 0 && (
                    <span className="text-xs text-muted-foreground" title="Critical and High findings with a fix">
                      {(w.fixable_critical ?? 0) + (w.fixable_high ?? 0)} fixable
                    </span>
                  )}
                  <ChevronRight className="h-4 w-4 text-muted-foreground/30 group-hover:text-primary group-hover:translate-x-0.5 transition-all ml-1" />
                </div>
              </button>
            ))}
            {data.top_vulnerable_workloads.length === 0 && (
              <div className="text-center py-8 text-muted-foreground flex flex-col items-center justify-center">
                <ShieldCheck className="h-8 w-8 text-green-500 mb-2" />
                No vulnerable workloads found
              </div>
            )}
          </div>
        </div>

        {/* Leaderboard */}
        <div className="rounded-2xl border bg-card p-5 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-semibold">
              {selectedCluster ? "Namespace Risk Density" : "Cluster Health Leaderboard"}
            </h3>
            <span className="text-xs text-muted-foreground">
              {selectedCluster ? `${data.vulnerable_namespaces?.length || 0} namespaces` : `${data.vulnerable_clusters?.length || 0} clusters`}
            </span>
          </div>
          <div className="space-y-2 flex-1 overflow-y-auto max-h-[300px] pr-1 scrollbar-thin">
            {!selectedCluster ? (
              data.vulnerable_clusters?.map((c) => (
                <button 
                  key={c.name}
                  onClick={() => onSelectCluster(c.name)}
                  className="w-full text-left p-3 rounded-xl hover:bg-muted/50 border bg-background/40 transition-colors flex items-center justify-between group"
                >
                  <span className="font-semibold text-sm truncate mr-3">{c.name}</span>
                  <div className="flex items-center gap-1.5 flex-shrink-0">
                    <span className="text-xs px-2 py-0.5 rounded bg-red-500/10 text-red-500 font-medium">{c.critical} Crit</span>
                    <span className="text-xs px-2 py-0.5 rounded bg-orange-500/10 text-orange-500 font-medium">{c.high} High</span>
                    <ChevronRight className="h-4 w-4 text-muted-foreground/30 group-hover:text-primary group-hover:translate-x-0.5 transition-all ml-1" />
                  </div>
                </button>
              ))
            ) : (
              data.vulnerable_namespaces?.map((ns) => (
                <button 
                  key={`${ns.cluster || selectedCluster}\x00${ns.name}`}
                  onClick={() => ns.name && onSelectNamespace(ns.name)}
                  className="w-full text-left p-3 rounded-xl hover:bg-muted/50 border bg-background/40 transition-colors flex items-center justify-between group"
                >
                  <span className="font-semibold text-sm truncate mr-3">{namespaceLabel(ns.name)}</span>
                  <div className="flex items-center gap-1.5 flex-shrink-0">
                    <span className="text-xs px-2 py-0.5 rounded bg-red-500/10 text-red-500 font-medium">{ns.critical} Crit</span>
                    <span className="text-xs px-2 py-0.5 rounded bg-orange-500/10 text-orange-500 font-medium">{ns.high} High</span>
                    <ChevronRight className="h-4 w-4 text-muted-foreground/30 group-hover:text-primary group-hover:translate-x-0.5 transition-all ml-1" />
                  </div>
                </button>
              ))
            )}
            {(!selectedCluster && (!data.vulnerable_clusters || data.vulnerable_clusters.length === 0)) ||
             (selectedCluster && (!data.vulnerable_namespaces || data.vulnerable_namespaces.length === 0)) ? (
              <div className="text-center py-8 text-muted-foreground flex flex-col items-center justify-center">
                <ShieldCheck className="h-8 w-8 text-green-500 mb-2" />
                Excellent health state
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  )
}

export const OverviewDashboard = React.memo(OverviewDashboardInternal)

