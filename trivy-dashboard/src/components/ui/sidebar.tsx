import { FileText, Shield, Server, Moon, Sun } from "lucide-react"
import { cn } from "@/lib/utils"
import { Combobox } from "./combobox"
import type { Cluster, ReportType } from "../../api/client"
import { useState, useEffect } from "react"

function formatTypeName(name: string): string {
  let formatted = name.replace(/Report$/i, "")
  formatted = formatted.replace(/([a-z])([A-Z])/g, "$1 $2")
  formatted = formatted.replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
  return formatted.trim()
}

export interface SidebarProps {
  clusters: Cluster[]
  reportTypes: ReportType[]
  reportCounts?: Record<string, number>
  selectedCluster?: string
  selectedType?: string
  onSelectCluster?: (cluster: string) => void
  onSelectType?: (type: string) => void
}

export function Sidebar({
  clusters,
  reportTypes,
  reportCounts = {},
  selectedCluster,
  selectedType,
  onSelectCluster,
  onSelectType,
}: SidebarProps) {
  const [isDark, setIsDark] = useState(() => {
    if (typeof window !== 'undefined') {
      return document.documentElement.classList.contains('dark')
    }
    return false
  })

  useEffect(() => {
    if (isDark) {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
    localStorage.setItem('theme', isDark ? 'dark' : 'light')
  }, [isDark])

  useEffect(() => {
    const savedTheme = localStorage.getItem('theme')
    if (savedTheme === 'dark') {
      setIsDark(true)
    } else if (savedTheme === 'light') {
      setIsDark(false)
    } else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
      setIsDark(true)
    }
  }, [])

  const clusterOptions = clusters.map((c) => ({ value: c.name, label: c.name }))

  const reportTypeOptions = reportTypes.map((t) => ({
    value: t.name,
    label: formatTypeName(t.kind || t.name),
  }))

  return (
    <div className="flex h-screen w-72 flex-col border-r bg-card/80 backdrop-blur-sm">
      {/* Logo Section */}
      <div className="flex h-20 items-center justify-between border-b px-6 bg-gradient-to-r from-primary/10 to-purple-500/10">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-gradient-to-br from-primary to-purple-600 shadow-lg shadow-primary/25">
            <Shield className="h-6 w-6 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-bold bg-clip-text text-transparent bg-gradient-to-r from-primary to-purple-600">
              Trivy UI
            </h1>
            <p className="text-[10px] text-muted-foreground font-medium">Security Dashboard</p>
          </div>
        </div>
        <button
          onClick={() => setIsDark(!isDark)}
          className="p-2 rounded-lg hover:bg-muted transition-colors"
          title={isDark ? "Switch to light mode" : "Switch to dark mode"}
        >
          {isDark ? (
            <Sun className="h-4 w-4 text-yellow-500" />
          ) : (
            <Moon className="h-4 w-4 text-slate-600" />
          )}
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-6 scrollbar-thin">
        {/* Cluster Selection */}
        <div>
          <label className="mb-2 flex items-center gap-2 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            <Server className="h-3.5 w-3.5" />
            Cluster
          </label>
          <Combobox
            options={clusterOptions}
            value={selectedCluster}
            onValueChange={onSelectCluster}
            placeholder="Select cluster..."
          />
        </div>

        {/* Report Type Selection */}
        <div>
          <label className="mb-2 flex items-center gap-2 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            <FileText className="h-3.5 w-3.5" />
            Report Type
          </label>
          <Combobox
            options={reportTypeOptions}
            value={selectedType}
            onValueChange={onSelectType}
            placeholder="Select report type..."
          />

          {/* Report Type List */}
          <nav className="mt-3 space-y-1">
            {reportTypes
              .sort((a, b) => {
                if (a.namespaced && !b.namespaced) return -1
                if (!a.namespaced && b.namespaced) return 1
                return 0
              })
              .map((type) => {
                const displayName = formatTypeName(type.kind || type.name)
                const count = reportCounts[type.name]
                const isSelected = selectedType === type.name

                return (
                  <button
                    key={type.name}
                    onClick={() => onSelectType?.(type.name)}
                    className={cn(
                      "flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition-all duration-200",
                      isSelected
                        ? "bg-gradient-to-r from-primary to-primary/80 text-primary-foreground shadow-lg shadow-primary/25"
                        : "hover:bg-muted/70 text-foreground/80 hover:text-foreground"
                    )}
                  >
                    <div className={cn(
                      "p-1.5 rounded-lg",
                      isSelected ? "bg-white/20" : "bg-muted"
                    )}>
                      <FileText className="h-3.5 w-3.5" />
                    </div>
                    <span className="flex-1 text-left truncate font-medium">{displayName}</span>
                    {count !== undefined && count > 0 && (
                      <span className={cn(
                        "flex-shrink-0 rounded-full px-2 py-0.5 min-w-[24px] text-center text-xs font-semibold",
                        isSelected
                          ? "bg-white/20 text-primary-foreground"
                          : "bg-primary/10 text-primary"
                      )}>
                        {count > 99 ? "99+" : count}
                      </span>
                    )}
                    {!type.namespaced && (
                      <span className={cn(
                        "text-[10px] font-medium px-1.5 py-0.5 rounded",
                        isSelected
                          ? "bg-white/20 text-primary-foreground"
                          : "bg-muted text-muted-foreground"
                      )}>
                        Cluster
                      </span>
                    )}
                  </button>
                )
              })}
          </nav>
        </div>
      </div>

      {/* Footer */}
      <div className="border-t p-4">
        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
            <span>Connected</span>
          </div>
          <span className="text-muted-foreground/40">•</span>
          <span>{clusters.length} clusters</span>
        </div>
      </div>
    </div>
  )
}
