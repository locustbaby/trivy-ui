import { FileText, Shield, Server, Moon, Sun, Menu, X, ChevronLeft } from "lucide-react"
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

  const [isCollapsed, setIsCollapsed] = useState(false)
  const [isMobileOpen, setIsMobileOpen] = useState(false)

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

  // Close mobile sidebar when clicking outside
  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth >= 768) {
        setIsMobileOpen(false)
      }
    }
    window.addEventListener('resize', handleResize)
    return () => window.removeEventListener('resize', handleResize)
  }, [])

  const clusterOptions = clusters.map((c) => ({ value: c.name, label: c.name }))

  const reportTypeOptions = reportTypes.map((t) => ({
    value: t.name,
    label: formatTypeName(t.kind || t.name),
  }))

  const sidebarContent = (
    <>
      {/* Logo Section */}
      <div className="flex h-20 items-center justify-between border-b px-4 md:px-6 bg-gradient-to-r from-primary/10 to-purple-500/10">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-gradient-to-br from-primary to-purple-600 shadow-lg shadow-primary/25">
            <Shield className="h-6 w-6 text-white" />
          </div>
          {!isCollapsed && (
            <div>
              <h1 className="text-lg font-bold bg-clip-text text-transparent bg-gradient-to-r from-primary to-purple-600">
                Trivy UI
              </h1>
              <p className="text-[10px] text-muted-foreground font-medium">Security Dashboard</p>
            </div>
          )}
        </div>
        <div className="flex items-center gap-1">
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
          {/* Collapse button - desktop only */}
          <button
            onClick={() => setIsCollapsed(!isCollapsed)}
            className="hidden md:flex p-2 rounded-lg hover:bg-muted transition-colors"
            title={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            <ChevronLeft className={cn("h-4 w-4 transition-transform", isCollapsed && "rotate-180")} />
          </button>
          {/* Close button - mobile only */}
          <button
            onClick={() => setIsMobileOpen(false)}
            className="md:hidden p-2 rounded-lg hover:bg-muted transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 md:p-5 space-y-6 scrollbar-thin">
        {/* Cluster Selection */}
        <div>
          <label className={cn(
            "mb-2 flex items-center gap-2 text-xs font-semibold text-muted-foreground uppercase tracking-wider",
            isCollapsed && "justify-center"
          )}>
            <Server className="h-3.5 w-3.5" />
            {!isCollapsed && "Cluster"}
          </label>
          {isCollapsed ? (
            <div className="flex justify-center">
              <div className="p-2 rounded-lg bg-muted" title={selectedCluster || "Select cluster"}>
                <Server className="h-4 w-4" />
              </div>
            </div>
          ) : (
            <Combobox
              options={clusterOptions}
              value={selectedCluster}
              onValueChange={onSelectCluster}
              placeholder="Select cluster..."
            />
          )}
        </div>

        {/* Report Type Selection */}
        <div>
          <label className={cn(
            "mb-2 flex items-center gap-2 text-xs font-semibold text-muted-foreground uppercase tracking-wider",
            isCollapsed && "justify-center"
          )}>
            <FileText className="h-3.5 w-3.5" />
            {!isCollapsed && "Report Type"}
          </label>
          {!isCollapsed && (
            <Combobox
              options={reportTypeOptions}
              value={selectedType}
              onValueChange={onSelectType}
              placeholder="Select report type..."
            />
          )}

          {/* Report Type List */}
          <nav className="mt-3 space-y-1">
            {reportTypes
              .slice() // Create a copy to avoid mutating the original array
              .sort((a, b) => {
                // 1. Namespaced reports first, then cluster-scoped
                if (a.namespaced && !b.namespaced) return -1
                if (!a.namespaced && b.namespaced) return 1
                // 2. Within each group, sort alphabetically by name
                return a.name.localeCompare(b.name)
              })
              .map((type) => {
                const displayName = formatTypeName(type.kind || type.name)
                const count = reportCounts[type.name]
                const isSelected = selectedType === type.name

                return (
                  <button
                    key={type.name}
                    onClick={() => {
                      onSelectType?.(type.name)
                      setIsMobileOpen(false)
                    }}
                    className={cn(
                      "flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition-all duration-200",
                      isCollapsed && "justify-center px-2",
                      isSelected
                        ? "bg-gradient-to-r from-primary to-primary/80 text-primary-foreground shadow-lg shadow-primary/25"
                        : "hover:bg-muted/70 text-foreground/80 hover:text-foreground"
                    )}
                    title={isCollapsed ? displayName : undefined}
                  >
                    <div className={cn(
                      "p-1.5 rounded-lg",
                      isSelected ? "bg-white/20" : "bg-muted"
                    )}>
                      <FileText className="h-3.5 w-3.5" />
                    </div>
                    {!isCollapsed && (
                      <>
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
                      </>
                    )}
                  </button>
                )
              })}
          </nav>
        </div>
      </div>

      {/* Footer */}
      <div className="border-t p-4">
        <div className={cn(
          "flex items-center gap-3 text-xs text-muted-foreground",
          isCollapsed && "justify-center"
        )}>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
            {!isCollapsed && <span>Connected</span>}
          </div>
          {!isCollapsed && (
            <>
              <span className="text-muted-foreground/40">•</span>
              <span>{clusters.length} clusters</span>
            </>
          )}
        </div>
      </div>
    </>
  )

  return (
    <>
      {/* Mobile menu button */}
      <button
        onClick={() => setIsMobileOpen(true)}
        className="md:hidden fixed top-4 left-4 z-50 p-2 rounded-lg bg-card border shadow-lg"
        aria-label="Open menu"
      >
        <Menu className="h-5 w-5" />
      </button>

      {/* Mobile overlay */}
      {isMobileOpen && (
        <div
          className="md:hidden fixed inset-0 bg-black/50 z-40"
          onClick={() => setIsMobileOpen(false)}
        />
      )}

      {/* Desktop sidebar */}
      <div className={cn(
        "hidden md:flex h-screen flex-col border-r bg-card/80 backdrop-blur-sm transition-all duration-300",
        isCollapsed ? "w-16" : "w-72"
      )}>
        {sidebarContent}
      </div>

      {/* Mobile sidebar */}
      <div className={cn(
        "md:hidden fixed inset-y-0 left-0 z-50 flex h-screen w-72 flex-col border-r bg-card shadow-xl transition-transform duration-300",
        isMobileOpen ? "translate-x-0" : "-translate-x-full"
      )}>
        {sidebarContent}
      </div>
    </>
  )
}
