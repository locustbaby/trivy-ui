import * as React from "react"
import { useEffect, useMemo, useRef, useState } from "react"
import { api } from "../api/client"
import type { ClusterOverview, TrendRecord, Cluster } from "../api/client"
import {
  Shield,
  Server,
  Activity,
  ShieldCheck,
  Loader2,
  X,
  AlertTriangle,
  AlertCircle,
  Info,
  ChevronRight,
  ArrowUpRight,
} from "lucide-react"
import { Button } from "./ui/button"
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer } from "recharts"

interface GlobalHubProps {
  clusters: Cluster[]
  onSelectCluster: (cluster: string) => void
}

function GlobalHubInternal({ clusters, onSelectCluster }: GlobalHubProps) {
  const [globalData, setGlobalData] = useState<ClusterOverview | null>(null)
  const [globalTrends, setGlobalTrends] = useState<TrendRecord[]>([])
  const [clusterTrends, setClusterTrends] = useState<Record<string, TrendRecord[]>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>()
  const [retryCount, setRetryCount] = useState(0)
  const generationRef = useRef(0)
  const clustersRef = useRef(clusters)
  clustersRef.current = clusters
  const clusterKey = clusters.map((cluster) => cluster.name).join("\x00")

  useEffect(() => {
    const generation = ++generationRef.current
    const controller = new AbortController()
    const load = async () => {
      setLoading(true)
      setError(undefined)
      try {
        const [ovData, trData] = await Promise.all([
          api.getOverview(undefined, controller.signal),
          api.getOverviewTrends(undefined, 30, controller.signal)
        ])
        if (generation !== generationRef.current) return
        setGlobalData(ovData)
        setGlobalTrends(trData.filter((point) => point.cluster === "" && !point.namespace))

        if (generation === generationRef.current) {
          const trendsMap: Record<string, TrendRecord[]> = {}
          for (const clusterName of clustersRef.current.map((cluster) => cluster.name)) {
            trendsMap[clusterName] = trData.filter((point) => point.cluster === clusterName && !point.namespace)
          }
          if (generation === generationRef.current) setClusterTrends(trendsMap)
        }
      } catch (e) {
        if (!(e instanceof Error && e.name === "AbortError")) {
          if (generation === generationRef.current) {
            setError(e instanceof Error ? e.message : "Failed to load fleet overview")
          }
        }
      } finally {
        if (generation === generationRef.current) setLoading(false)
      }
    }
    load()
    return () => controller.abort()
  }, [clusterKey, retryCount])

  const chartData = useMemo(() => globalTrends.map(t => {
    const d = new Date(t.timestamp)
    return {
      name: `${d.getMonth()+1}/${d.getDate()} ${String(d.getHours()).padStart(2, '0')}:00`,
      critical: t.critical,
      high: t.high,
    }
  }), [globalTrends])

  const clusterHealth = useMemo(() => {
    return new Map((globalData?.vulnerable_clusters || []).map((cluster) => [cluster.name, cluster]))
  }, [globalData?.vulnerable_clusters])

  const miniTrends = useMemo(() => {
    return Object.fromEntries(Object.entries(clusterTrends).map(([name, trend]) => [
      name,
      trend.map((point) => ({ value: point.critical + point.high })),
    ])) as Record<string, { value: number }[]>
  }, [clusterTrends])

  const getMiniSparkline = (cname: string) => {
    return miniTrends[cname] || []
  }

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-4 text-muted-foreground">
          <Loader2 className="h-10 w-10 animate-spin" />
          <p className="text-sm">Loading Fleet Overview...</p>
        </div>
      </div>
    )
  }

  if (!globalData && error && !loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background p-6">
        <div className="flex flex-col items-center gap-4 p-8 rounded-2xl bg-card border shadow-xl max-w-md">
          <X className="h-12 w-12 text-destructive mb-1" />
          <div className="text-destructive font-medium text-center">{error}</div>
          <Button onClick={() => setRetryCount((count) => count + 1)} size="sm">Retry</Button>
        </div>
      </div>
    )
  }

  if (!globalData) return null

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted/20 overflow-y-auto scrollbar-thin">
      <div className="mx-auto max-w-7xl p-6 sm:p-8 space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500 ease-out">
        
        {/* Header Section */}
        <header className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-6">
          <div className="flex items-center gap-3.5">
            <div className="p-3 rounded-2xl bg-gradient-to-br from-primary to-purple-600 shadow-md shadow-primary/20 text-white flex-shrink-0">
              <Shield className="h-7 w-7" />
            </div>
            <div>
              <div className="flex items-center gap-2.5 flex-wrap">
                <h1 className="text-2xl sm:text-3xl font-bold tracking-tight">Fleet Security Hub</h1>
                <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-primary/10 text-primary border border-primary/20">
                  {clusters.length} Clusters Connected
                </span>
              </div>
              <p className="text-xs sm:text-sm text-muted-foreground mt-0.5">
                Global vulnerability tracking and cross-cluster security analytics
              </p>
            </div>
          </div>
        </header>

        {/* Severity Totals Row */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { label: "Critical", count: globalData.severity_totals.critical, icon: Shield, color: "text-red-500", bg: "bg-red-500/10 border-red-500/20" },
            { label: "High", count: globalData.severity_totals.high, icon: AlertTriangle, color: "text-orange-500", bg: "bg-orange-500/10 border-orange-500/20" },
            { label: "Medium", count: globalData.severity_totals.medium, icon: AlertCircle, color: "text-yellow-500", bg: "bg-yellow-500/10 border-yellow-500/20" },
            { label: "Low", count: globalData.severity_totals.low, icon: Info, color: "text-blue-500", bg: "bg-blue-500/10 border-blue-500/20" }
          ].map((sev, idx) => (
            <div key={idx} className={`p-4 rounded-2xl border ${sev.bg} flex items-center justify-between shadow-xs`}>
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">{sev.label}</p>
                <h3 className={`text-2xl sm:text-3xl font-bold mt-1 tracking-tight ${sev.color}`}>{sev.count.toLocaleString()}</h3>
              </div>
              <div className="p-2.5 rounded-xl bg-background/50 border shadow-xs">
                <sev.icon className={`h-5 w-5 ${sev.color}`} />
              </div>
            </div>
          ))}
        </div>

        {/* Trend Chart & Cluster Ranking */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-stretch">
          {/* Global Trend Chart */}
          <div className="lg:col-span-2 rounded-2xl border bg-card p-5 shadow-sm flex flex-col justify-between">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-base font-semibold flex items-center gap-2">
                  <Activity className="h-4 w-4 text-primary" />
                  Fleet Vulnerability Trend (30 Days)
                </h3>
                <p className="text-xs text-muted-foreground mt-0.5">Aggregated critical and high vulnerabilities across all clusters</p>
              </div>
            </div>
            <div className="h-[280px] w-full flex-1 min-h-[220px]">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="globalColorCritical" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="globalColorHigh" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f97316" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#f97316" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="currentColor" className="text-muted-foreground/10" />
                  <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fontSize: 12 }} stroke="currentColor" className="text-muted-foreground" />
                  <YAxis axisLine={false} tickLine={false} tick={{ fontSize: 12 }} stroke="currentColor" className="text-muted-foreground" />
                  <RechartsTooltip contentStyle={{ backgroundColor: 'hsl(var(--card))', borderColor: 'hsl(var(--border))', borderRadius: '12px', boxShadow: '0 10px 15px -3px rgb(0 0 0 / 0.1)' }} />
                  <Area type="monotone" dataKey="critical" stroke="#ef4444" fillOpacity={1} fill="url(#globalColorCritical)" strokeWidth={2.5} />
                  <Area type="monotone" dataKey="high" stroke="#f97316" fillOpacity={1} fill="url(#globalColorHigh)" strokeWidth={2.5} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Cluster Risk Ranking */}
          <div className="rounded-2xl border bg-card p-5 shadow-sm flex flex-col justify-between">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-base font-semibold flex items-center gap-2">
                <Server className="h-4 w-4 text-primary" />
                Cluster Risk Ranking
              </h3>
              <span className="text-xs text-muted-foreground">{clusters.length} total</span>
            </div>
            <div className="space-y-2 flex-1 overflow-y-auto max-h-[280px] pr-1 scrollbar-thin">
              {globalData.vulnerable_clusters?.map((c) => (
                <button
                  key={c.name}
                  onClick={() => onSelectCluster(c.name)}
                  className="w-full text-left p-3 rounded-xl hover:bg-muted/50 border bg-background/40 transition-colors flex items-center justify-between group"
                >
                  <div className="min-w-0 mr-2">
                    <p className="font-semibold text-xs sm:text-sm truncate group-hover:text-primary transition-colors">{c.name}</p>
                  </div>
                  <div className="flex items-center gap-1.5 flex-shrink-0">
                    {c.critical > 0 && <span className="text-[11px] px-2 py-0.5 rounded bg-red-500/10 text-red-500 font-medium">{c.critical.toLocaleString()} Crit</span>}
                    {c.high > 0 && <span className="text-[11px] px-2 py-0.5 rounded bg-orange-500/10 text-orange-500 font-medium">{c.high.toLocaleString()} High</span>}
                    {c.critical === 0 && c.high === 0 && (
                      <span className="text-[11px] text-emerald-600 dark:text-emerald-400 font-medium flex items-center gap-1">
                        <ShieldCheck className="h-3.5 w-3.5" /> Healthy
                      </span>
                    )}
                    <ChevronRight className="h-4 w-4 text-muted-foreground/30 group-hover:text-primary group-hover:translate-x-0.5 transition-all ml-1" />
                  </div>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Clusters Directory */}
        <div>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Server className="h-4 w-4 text-primary" />
              <h3 className="text-base font-semibold">Cluster Directory</h3>
            </div>
            <span className="text-xs text-muted-foreground">Select a cluster to drill into details</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {clusters.map((c) => {
              const healthData = clusterHealth.get(c.name)
              const crit = healthData?.critical || 0
              const high = healthData?.high || 0
              const sparklineData = getMiniSparkline(c.name)
              const isHealthy = crit === 0 && high === 0

              return (
                <button
                  key={c.name}
                  onClick={() => onSelectCluster(c.name)}
                  className="group text-left p-5 rounded-2xl border bg-card hover:bg-muted/40 hover:border-primary/40 hover:shadow-md transition-all duration-200 flex flex-col relative overflow-hidden cursor-pointer"
                >
                  <div className="flex items-start justify-between gap-2 mb-3">
                    <div className="min-w-0">
                      <h4 className="text-base font-bold truncate group-hover:text-primary transition-colors">{c.name}</h4>
                      <div className="flex items-center gap-1.5 mt-1 text-xs text-muted-foreground">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                        <span>{c.syncState || 'Fully Synced'}</span>
                      </div>
                    </div>
                    {isHealthy ? (
                      <span className="p-1 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                        <ShieldCheck className="h-4 w-4" />
                      </span>
                    ) : (
                      <ArrowUpRight className="h-4 w-4 text-muted-foreground/40 group-hover:text-primary group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-all" />
                    )}
                  </div>

                  <div className="grid grid-cols-2 gap-3 py-3 border-y bg-background/30 rounded-xl px-3 my-2">
                    <div>
                      <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Critical</p>
                      <p className={`text-xl font-bold ${crit > 0 ? 'text-red-500' : 'text-muted-foreground/30'}`}>{crit.toLocaleString()}</p>
                    </div>
                    <div>
                      <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">High</p>
                      <p className={`text-xl font-bold ${high > 0 ? 'text-orange-500' : 'text-muted-foreground/30'}`}>{high.toLocaleString()}</p>
                    </div>
                  </div>

                  {/* Mini Sparkline */}
                  <div className="h-10 w-full mt-2 opacity-60 group-hover:opacity-100 transition-opacity">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={sparklineData}>
                        <Area 
                          type="monotone" 
                          dataKey="value" 
                          stroke={crit > 0 ? "#ef4444" : (high > 0 ? "#f97316" : "#22c55e")} 
                          fill={crit > 0 ? "#ef444420" : (high > 0 ? "#f9731620" : "#22c55e20")} 
                          strokeWidth={2}
                          isAnimationActive={false}
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </button>
              )
            })}
          </div>
        </div>

      </div>
    </div>
  )
}

export const GlobalHub = React.memo(GlobalHubInternal)

