import * as React from "react"
import { useEffect, useMemo, useRef, useState } from "react"
import { api } from "../api/client"
import type { ClusterOverview, TrendRecord, WorkloadSummary } from "../api/client"
import { Shield, AlertTriangle, AlertCircle, Info, ShieldCheck, Loader2, X } from "lucide-react"
import { Button } from "./ui/button"
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts"

interface OverviewDashboardProps {
  selectedCluster?: string
  onSelectNamespace: (ns: string) => void
  onSelectWorkload: (w: WorkloadSummary) => void
  onSelectCluster: (cluster: string) => void
}

function OverviewDashboardInternal({ selectedCluster, onSelectNamespace, onSelectWorkload, onSelectCluster }: OverviewDashboardProps) {
  const [data, setData] = useState<ClusterOverview | null>(null)
  const [trends, setTrends] = useState<TrendRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>()
  const [retryCount, setRetryCount] = useState(0)
  const generationRef = useRef(0)

  useEffect(() => {
    const generation = ++generationRef.current
    const controller = new AbortController()
    setData(null)
    setTrends([])
    setError(undefined)
    const load = async () => {
      setLoading(true)
      try {
        const [ovData, trData] = await Promise.all([
          api.getOverview(selectedCluster, controller.signal),
          api.getOverviewTrends(selectedCluster, 30, controller.signal)
        ])
        if (generation === generationRef.current) {
          setData(ovData)
          setTrends(trData)
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
  }, [selectedCluster, retryCount])

	const chartData = useMemo(() => trends.map(t => {
    const d = new Date(t.timestamp)
    return {
      name: `${d.getMonth()+1}/${d.getDate()} ${String(d.getHours()).padStart(2, '0')}:00`,
      critical: t.critical,
      high: t.high,
      medium: t.medium
    }
	}), [trends])

	if (loading) {
		return (
			<div className="flex h-[60vh] items-center justify-center">
				<Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
			</div>
		)
	}

	if (error && !loading) {
		return (
			<div className="flex flex-col items-center justify-center py-16 rounded-2xl border bg-card/50">
				<X className="h-12 w-12 text-destructive mb-3" />
				<div className="mb-4 text-destructive font-medium">{error}</div>
				<Button onClick={() => setRetryCount((count) => count + 1)} size="sm">Retry</Button>
			</div>
		)
	}

	if (!data) return null

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500 ease-out">
      {/* Severities Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "Critical", count: data.severity_totals.critical, icon: Shield, color: "text-red-500", bg: "bg-red-500/10 border-red-500/20" },
          { label: "High", count: data.severity_totals.high, icon: AlertTriangle, color: "text-orange-500", bg: "bg-orange-500/10 border-orange-500/20" },
          { label: "Medium", count: data.severity_totals.medium, icon: AlertCircle, color: "text-yellow-500", bg: "bg-yellow-500/10 border-yellow-500/20" },
          { label: "Low", count: data.severity_totals.low, icon: Info, color: "text-blue-500", bg: "bg-blue-500/10 border-blue-500/20" }
        ].map((sev, idx) => (
          <div key={idx} className={`p-4 rounded-2xl border ${sev.bg} flex items-center justify-between`}>
            <div>
              <p className="text-sm font-medium text-muted-foreground">{sev.label}</p>
              <h3 className={`text-3xl font-bold mt-1 ${sev.color}`}>{sev.count}</h3>
            </div>
            <div className={`p-3 rounded-full bg-white/5`}>
              <sev.icon className={`h-6 w-6 ${sev.color}`} />
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Trend Chart */}
        <div className="lg:col-span-2 rounded-2xl border bg-card p-5 shadow-sm">
          <h3 className="text-lg font-semibold mb-4">30-Day Trend</h3>
          <div className="h-[250px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 5, right: 0, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f97316" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#f97316" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="currentColor" className="text-muted-foreground/20" />
                <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fontSize: 12 }} stroke="currentColor" className="text-muted-foreground" />
                <YAxis axisLine={false} tickLine={false} tick={{ fontSize: 12 }} stroke="currentColor" className="text-muted-foreground" />
                <Tooltip contentStyle={{ backgroundColor: 'hsl(var(--card))', borderColor: 'hsl(var(--border))', borderRadius: '8px' }} />
                <Area type="monotone" dataKey="critical" stroke="#ef4444" fillOpacity={1} fill="url(#colorCritical)" strokeWidth={2} />
                <Area type="monotone" dataKey="high" stroke="#f97316" fillOpacity={1} fill="url(#colorHigh)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Scan Category Matrix */}
        <div className="rounded-2xl border bg-card p-5 shadow-sm">
          <h3 className="text-lg font-semibold mb-4">Scan Breakdown</h3>
          <div className="space-y-4">
            {Object.entries(data.scan_types_breakdown).map(([type, stats]) => {
              const passRate = stats.scanned > 0 ? Math.round(((stats.scanned - stats.failed) / stats.scanned) * 100) : 100
              const isHealthy = passRate > 80
              return (
                <div key={type}>
                  <div className="flex justify-between text-sm mb-1.5">
                    <span className="font-medium truncate mr-2" title={type}>{type}</span>
                    <span className="text-muted-foreground whitespace-nowrap">{passRate}% Pass</span>
                  </div>
                  <div className="h-2.5 w-full bg-secondary rounded-full overflow-hidden">
                    <div 
                      className={`h-full rounded-full ${isHealthy ? 'bg-green-500' : 'bg-orange-500'}`} 
                      style={{ width: `${passRate}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-[10px] mt-1 text-muted-foreground">
                    <span>{stats.scanned} Total</span>
                    <span>{stats.failed} Failed</span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Vulnerable Workloads */}
        <div className="rounded-2xl border bg-card p-5 shadow-sm">
          <h3 className="text-lg font-semibold mb-4">Top Vulnerable Workloads</h3>
          <div className="space-y-3">
            {data.top_vulnerable_workloads.map((w) => (
              <button 
                key={JSON.stringify([w.cluster, w.namespace, w.type, w.name])}
                onClick={() => onSelectWorkload(w)}
                className="w-full text-left p-3 rounded-xl hover:bg-muted/50 border border-transparent hover:border-border transition-colors flex items-center justify-between group"
              >
                <div className="overflow-hidden">
                  <p className="font-medium truncate">{w.name}</p>
                  <p className="text-xs text-muted-foreground truncate">{w.namespace} • {w.type}</p>
                </div>
                <div className="flex gap-2">
                  {w.critical > 0 && <span className="text-xs px-2 py-0.5 rounded bg-red-500/10 text-red-500 font-medium">{w.critical} Crit</span>}
                  {w.high > 0 && <span className="text-xs px-2 py-0.5 rounded bg-orange-500/10 text-orange-500 font-medium">{w.high} High</span>}
                </div>
              </button>
            ))}
            {data.top_vulnerable_workloads.length === 0 && (
              <div className="text-center py-6 text-muted-foreground flex flex-col items-center">
                <ShieldCheck className="h-8 w-8 text-green-500 mb-2" />
                No vulnerable workloads found
              </div>
            )}
          </div>
        </div>

        {/* Leaderboard */}
        <div className="rounded-2xl border bg-card p-5 shadow-sm">
          <h3 className="text-lg font-semibold mb-4">
            {selectedCluster ? "Namespace Risk Density" : "Cluster Health Leaderboard"}
          </h3>
          <div className="space-y-3">
            {!selectedCluster ? (
              data.vulnerable_clusters?.map((c) => (
                <button 
                  key={c.name}
                  onClick={() => onSelectCluster(c.name)}
                  className="w-full text-left p-3 rounded-xl hover:bg-muted/50 border border-transparent hover:border-border transition-colors flex items-center justify-between"
                >
                  <span className="font-medium truncate">{c.name}</span>
                  <div className="flex gap-2">
                    <span className="text-xs px-2 py-0.5 rounded bg-red-500/10 text-red-500 font-medium">{c.critical} Crit</span>
                    <span className="text-xs px-2 py-0.5 rounded bg-orange-500/10 text-orange-500 font-medium">{c.high} High</span>
                  </div>
                </button>
              ))
            ) : (
              data.vulnerable_namespaces?.map((ns) => (
                <button 
                  key={`${ns.cluster || selectedCluster}\x00${ns.name}`}
                  onClick={() => onSelectNamespace(ns.name)}
                  className="w-full text-left p-3 rounded-xl hover:bg-muted/50 border border-transparent hover:border-border transition-colors flex items-center justify-between"
                >
                  <span className="font-medium truncate">{ns.name}</span>
                  <div className="flex gap-2">
                    <span className="text-xs px-2 py-0.5 rounded bg-red-500/10 text-red-500 font-medium">{ns.critical} Crit</span>
                    <span className="text-xs px-2 py-0.5 rounded bg-orange-500/10 text-orange-500 font-medium">{ns.high} High</span>
                  </div>
                </button>
              ))
            )}
            {(!selectedCluster && (!data.vulnerable_clusters || data.vulnerable_clusters.length === 0)) ||
             (selectedCluster && (!data.vulnerable_namespaces || data.vulnerable_namespaces.length === 0)) ? (
              <div className="text-center py-6 text-muted-foreground flex flex-col items-center">
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
