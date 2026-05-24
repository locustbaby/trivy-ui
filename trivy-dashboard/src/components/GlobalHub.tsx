import { useEffect, useState } from "react"
import { api } from "../api/client"
import type { ClusterOverview, TrendRecord, Cluster } from "../api/client"
import { Shield, Server, Activity, ShieldCheck, Loader2 } from "lucide-react"
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer } from "recharts"

interface GlobalHubProps {
  clusters: Cluster[]
  onSelectCluster: (cluster: string) => void
}

export function GlobalHub({ clusters, onSelectCluster }: GlobalHubProps) {
  const [globalData, setGlobalData] = useState<ClusterOverview | null>(null)
  const [globalTrends, setGlobalTrends] = useState<TrendRecord[]>([])
  const [clusterTrends, setClusterTrends] = useState<Record<string, TrendRecord[]>>({})
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = async () => {
      setLoading(true)
      try {
        const [ovData, trData] = await Promise.all([
          api.getOverview(),
          api.getOverviewTrends()
        ])
        setGlobalData(ovData)
        setGlobalTrends(trData)

        // Fetch mini trends for all clusters in parallel
        if (clusters.length > 0) {
          const trendsMap: Record<string, TrendRecord[]> = {}
          await Promise.all(
            clusters.map(async (c) => {
              const ct = await api.getOverviewTrends(c.name)
              trendsMap[c.name] = ct
            })
          )
          setClusterTrends(trendsMap)
        }
      } catch (e) {
        console.error(e)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [clusters])

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-4 text-muted-foreground">
          <Loader2 className="h-10 w-10 animate-spin" />
          <p>Loading Fleet Overview...</p>
        </div>
      </div>
    )
  }

  if (!globalData) return null

  const chartData = globalTrends.map(t => {
    const d = new Date(t.timestamp)
    return {
      name: `${d.getMonth()+1}/${d.getDate()} ${String(d.getHours()).padStart(2, '0')}:00`,
      critical: t.critical,
      high: t.high,
    }
  })

  // Format cluster specific mini-trends
  const getMiniSparkline = (cname: string) => {
    const trends = clusterTrends[cname] || []
    return trends.map(t => ({ value: t.critical + t.high }))
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted/30 overflow-y-auto scrollbar-thin">
      <div className="mx-auto max-w-7xl p-8 space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500 ease-out">
        
        {/* Header Section */}
        <header className="flex flex-col md:flex-row md:items-end justify-between gap-6 border-b pb-6">
          <div className="flex items-center gap-4">
            <div className="p-4 rounded-2xl bg-gradient-to-br from-primary to-purple-600 shadow-xl shadow-primary/25">
              <Shield className="h-10 w-10 text-white" />
            </div>
            <div>
              <h1 className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-primary to-purple-600 tracking-tight">
                Fleet Security Hub
              </h1>
              <p className="text-muted-foreground mt-2">Global vulnerability tracking and cross-cluster analytics</p>
            </div>
          </div>
          <div className="flex gap-6">
            <div className="text-right">
              <p className="text-sm font-medium text-muted-foreground uppercase tracking-wider">Critical Vulns</p>
              <p className="text-4xl font-black text-red-500">{globalData.severity_totals.critical}</p>
            </div>
            <div className="text-right">
              <p className="text-sm font-medium text-muted-foreground uppercase tracking-wider">High Vulns</p>
              <p className="text-4xl font-black text-orange-500">{globalData.severity_totals.high}</p>
            </div>
          </div>
        </header>

        {/* Global Trend Chart */}
        <div className="rounded-2xl border bg-card p-6 shadow-sm">
          <div className="flex items-center gap-2 mb-6">
            <Activity className="h-5 w-5 text-primary" />
            <h3 className="text-xl font-semibold">Fleet Vulnerability Trend (30 Days)</h3>
          </div>
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 5, right: 0, left: -20, bottom: 0 }}>
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
                <Area type="monotone" dataKey="critical" stroke="#ef4444" fillOpacity={1} fill="url(#globalColorCritical)" strokeWidth={3} />
                <Area type="monotone" dataKey="high" stroke="#f97316" fillOpacity={1} fill="url(#globalColorHigh)" strokeWidth={3} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Clusters Grid */}
        <div>
          <div className="flex items-center gap-2 mb-6">
            <Server className="h-5 w-5 text-primary" />
            <h3 className="text-xl font-semibold">Cluster Directory</h3>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
            {clusters.map((c) => {
              // Find health data for this cluster
              const healthData = globalData.vulnerable_clusters?.find(vc => vc.name === c.name)
              const crit = healthData?.critical || 0
              const high = healthData?.high || 0
              const sparklineData = getMiniSparkline(c.name)
              const isHealthy = crit === 0 && high === 0

              return (
                <button
                  key={c.name}
                  onClick={() => onSelectCluster(c.name)}
                  className="group text-left p-6 rounded-2xl border bg-card hover:bg-muted/50 hover:border-primary/50 transition-all duration-300 shadow-sm hover:shadow-md flex flex-col relative overflow-hidden"
                >
                  {isHealthy && (
                    <div className="absolute top-0 right-0 p-3">
                      <ShieldCheck className="h-5 w-5 text-green-500" />
                    </div>
                  )}
                  <h4 className="text-lg font-bold mb-1 truncate pr-8">{c.name}</h4>
                  <p className="text-xs text-muted-foreground mb-6">State: {c.syncState || 'Active'}</p>
                  
                  <div className="grid grid-cols-2 gap-4 mb-6">
                    <div>
                      <p className="text-xs font-medium text-muted-foreground uppercase">Critical</p>
                      <p className={`text-2xl font-black ${crit > 0 ? 'text-red-500' : 'text-muted-foreground/30'}`}>{crit}</p>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-muted-foreground uppercase">High</p>
                      <p className={`text-2xl font-black ${high > 0 ? 'text-orange-500' : 'text-muted-foreground/30'}`}>{high}</p>
                    </div>
                  </div>

                  {/* Mini Sparkline */}
                  <div className="h-12 w-full mt-auto opacity-50 group-hover:opacity-100 transition-opacity">
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
