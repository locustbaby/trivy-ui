import {
  FileText,
  Shield,
  Server,
  Moon,
  Sun,
  Menu,
  X,
  ChevronLeft,
  Bug,
  ClipboardCheck,
  KeyRound,
  Cpu,
  Users,
  Boxes,
  ShieldCheck,
  LayoutDashboard,
  GripVertical,
  Search,
} from "lucide-react"
import { cn, formatReportTypeName } from "@/lib/utils"
import { Combobox } from "./combobox"
import type { Cluster, ReportType } from "../../api/client"
import { useState, useEffect, useMemo, useRef, useCallback } from "react"

export interface SidebarProps {
  clusters: Cluster[]
  reportTypes: ReportType[]
  reportCounts?: Record<string, number>
  selectedCluster?: string
  selectedType?: string
  isSingleClusterMode?: boolean
  onSelectCluster?: (cluster: string) => void
  onSelectType?: (type: string) => void
}

const DEFAULT_SIDEBAR_WIDTH = 280
const MIN_SIDEBAR_WIDTH = 220
const MAX_SIDEBAR_WIDTH = 480
const SIDEBAR_WIDTH_KEY = "trivy-ui-sidebar-width"

function getInitialTheme(): boolean {
  if (typeof window === "undefined") return false
  const savedTheme = localStorage.getItem("theme")
  if (savedTheme === "dark") return true
  if (savedTheme === "light") return false
  return window.matchMedia("(prefers-color-scheme: dark)").matches
}

function getInitialWidth(): number {
  if (typeof window === "undefined") return DEFAULT_SIDEBAR_WIDTH
  const saved = localStorage.getItem(SIDEBAR_WIDTH_KEY)
  const parsed = saved ? parseInt(saved, 10) : NaN
  return !isNaN(parsed) && parsed >= MIN_SIDEBAR_WIDTH && parsed <= MAX_SIDEBAR_WIDTH
    ? parsed
    : DEFAULT_SIDEBAR_WIDTH
}

function getReportTypeIcon(kindOrName: string) {
  const lower = kindOrName.toLowerCase()
  if (lower.includes("vulnerab")) return Bug
  if (lower.includes("config")) return ClipboardCheck
  if (lower.includes("secret")) return KeyRound
  if (lower.includes("infra")) return Cpu
  if (lower.includes("rbac")) return Users
  if (lower.includes("sbom")) return Boxes
  if (lower.includes("complian")) return ShieldCheck
  return FileText
}

function getReportTypeIconColor(kindOrName: string, isSelected: boolean) {
  if (isSelected) return "text-primary-foreground"
  const lower = kindOrName.toLowerCase()
  if (lower.includes("vulnerab")) return "text-red-500 dark:text-red-400"
  if (lower.includes("config")) return "text-blue-500 dark:text-blue-400"
  if (lower.includes("secret")) return "text-amber-500 dark:text-amber-400"
  if (lower.includes("infra")) return "text-indigo-500 dark:text-indigo-400"
  if (lower.includes("rbac")) return "text-purple-500 dark:text-purple-400"
  if (lower.includes("sbom")) return "text-emerald-500 dark:text-emerald-400"
  if (lower.includes("complian")) return "text-teal-500 dark:text-teal-400"
  return "text-muted-foreground"
}

export function Sidebar({
  clusters,
  reportTypes,
  reportCounts = {},
  selectedCluster,
  selectedType,
  isSingleClusterMode = false,
  onSelectCluster,
  onSelectType,
}: SidebarProps) {
  const [isDark, setIsDark] = useState(getInitialTheme)
  const [isCollapsed, setIsCollapsed] = useState(false)
  const [isMobileOpen, setIsMobileOpen] = useState(false)
  const [sidebarWidth, setSidebarWidth] = useState(getInitialWidth)
  const [isResizing, setIsResizing] = useState(false)
  const [typeFilterQuery, setTypeFilterQuery] = useState("")
  const isDraggingRef = useRef(false)

  useEffect(() => {
    if (isDark) {
      document.documentElement.classList.add("dark")
    } else {
      document.documentElement.classList.remove("dark")
    }
    localStorage.setItem("theme", isDark ? "dark" : "light")
  }, [isDark])

  // Close mobile sidebar on resize
  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth >= 768) {
        setIsMobileOpen(false)
      }
    }
    window.addEventListener("resize", handleResize)
    return () => window.removeEventListener("resize", handleResize)
  }, [])

  // Drag handle to resize sidebar
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (isCollapsed) return
    e.preventDefault()
    isDraggingRef.current = true
    setIsResizing(true)
    document.body.style.cursor = "col-resize"
    document.body.style.userSelect = "none"

    const handleMouseMove = (event: MouseEvent) => {
      if (!isDraggingRef.current) return
      const newWidth = Math.min(Math.max(event.clientX, MIN_SIDEBAR_WIDTH), MAX_SIDEBAR_WIDTH)
      setSidebarWidth(newWidth)
    }

    const handleMouseUp = () => {
      if (!isDraggingRef.current) return
      isDraggingRef.current = false
      setIsResizing(false)
      document.body.style.cursor = ""
      document.body.style.userSelect = ""
      setSidebarWidth((w) => {
        localStorage.setItem(SIDEBAR_WIDTH_KEY, String(w))
        return w
      })
      window.removeEventListener("mousemove", handleMouseMove)
      window.removeEventListener("mouseup", handleMouseUp)
    }

    window.addEventListener("mousemove", handleMouseMove)
    window.addEventListener("mouseup", handleMouseUp)
  }, [isCollapsed])

  const handleResetWidth = useCallback(() => {
    setSidebarWidth(DEFAULT_SIDEBAR_WIDTH)
    localStorage.setItem(SIDEBAR_WIDTH_KEY, String(DEFAULT_SIDEBAR_WIDTH))
  }, [])

  const clusterOptions = useMemo(() => clusters.length > 1
    ? [
        { value: "all", label: "🌐 All Clusters" },
        ...clusters.map((c) => ({ value: c.name, label: c.name }))
      ]
    : clusters.map((c) => ({ value: c.name, label: c.name })), [clusters])

  const sortedReportTypes = useMemo(() => reportTypes.slice().sort((a, b) => {
    if (a.namespaced && !b.namespaced) return -1
    if (!a.namespaced && b.namespaced) return 1
    return a.name.localeCompare(b.name)
  }), [reportTypes])

  const filteredReportTypes = useMemo(() => {
    if (!typeFilterQuery.trim()) return sortedReportTypes
    const q = typeFilterQuery.toLowerCase().trim()
    return sortedReportTypes.filter(
      (t) =>
        t.name.toLowerCase().includes(q) ||
        (t.kind && t.kind.toLowerCase().includes(q)) ||
        formatReportTypeName(t.kind || t.name).toLowerCase().includes(q)
    )
  }, [sortedReportTypes, typeFilterQuery])

  const reportTypeOptions = useMemo(() => sortedReportTypes.map((t) => ({
    value: t.name,
    label: formatReportTypeName(t.kind || t.name),
  })), [sortedReportTypes])

  const currentClusterObj = clusters.find((c) => c.name === selectedCluster)
  const syncState = currentClusterObj?.syncState || "Cached"

  const syncStateConfig = {
    FullySynced: { color: "bg-green-500", text: "Fully Synced" },
    Syncing: { color: "bg-blue-500 animate-pulse", text: "Syncing..." },
    SyncFailed: { color: "bg-red-500 animate-pulse", text: "Sync Failed" },
    Cached: { color: "bg-gray-400", text: "Cached Snapshot" },
  }[syncState as "FullySynced" | "Syncing" | "SyncFailed" | "Cached"] || { color: "bg-gray-400", text: "Cached" }

  const sidebarContent = (
    <>
      {/* Logo Section */}
      <div className="flex h-16 items-center justify-between border-b px-4 bg-gradient-to-r from-primary/10 to-purple-500/10">
        <button 
          onClick={() => {
            onSelectType?.("")
            setIsMobileOpen(false)
          }}
          className={cn(
            "flex items-center gap-3 transition-opacity text-left rounded-xl outline-none ring-offset-background focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
            !selectedType ? "opacity-100" : "hover:opacity-80"
          )}
          title="Go to Overview"
        >
          <div className="p-2 rounded-xl bg-gradient-to-br from-primary to-purple-600 shadow-lg shadow-primary/25">
            <Shield className="h-5 w-5 text-white" />
          </div>
          {!isCollapsed && (
            <div>
              <h1 className="text-base font-bold bg-clip-text text-transparent bg-gradient-to-r from-primary to-purple-600 leading-tight">
                Trivy UI
              </h1>
              <p className="text-[10px] text-muted-foreground font-medium">Security Dashboard</p>
            </div>
          )}
        </button>
        <div className="flex items-center gap-1">
          <button
            onClick={() => setIsDark(!isDark)}
            className="p-1.5 rounded-lg hover:bg-muted transition-colors"
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
            className="hidden md:flex p-1.5 rounded-lg hover:bg-muted transition-colors"
            title={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            <ChevronLeft className={cn("h-4 w-4 transition-transform", isCollapsed && "rotate-180")} />
          </button>
          {/* Close button - mobile only */}
          <button
            onClick={() => setIsMobileOpen(false)}
            className="md:hidden p-1.5 rounded-lg hover:bg-muted transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-3 space-y-4 scrollbar-thin">
        {/* Navigation: Overview Button */}
        <div>
          <button
            onClick={() => {
              onSelectType?.("")
              setIsMobileOpen(false)
            }}
            className={cn(
              "flex w-full items-center gap-2.5 rounded-xl px-3 py-2 text-sm transition-all duration-200",
              isCollapsed && "justify-center px-2",
              !selectedType
                ? "bg-gradient-to-r from-primary to-primary/85 text-primary-foreground shadow-md shadow-primary/20 font-semibold"
                : "hover:bg-muted/70 text-foreground/80 hover:text-foreground font-medium"
            )}
            title={isCollapsed ? "Cluster Overview" : undefined}
          >
            <div className={cn("p-1.5 rounded-lg", !selectedType ? "bg-white/20" : "bg-muted")}>
              <LayoutDashboard className={cn("h-4 w-4", !selectedType ? "text-primary-foreground" : "text-primary")} />
            </div>
            {!isCollapsed && <span className="flex-1 text-left truncate">Overview</span>}
          </button>
        </div>

        {/* Cluster Selection */}
        {!isSingleClusterMode && (
          <div>
            <label className={cn(
              "mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground uppercase tracking-wider",
              isCollapsed && "justify-center"
            )}>
              <Server className="h-3 w-3" />
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
        )}

        {/* Report Type Section */}
        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label className={cn(
              "flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground uppercase tracking-wider",
              isCollapsed && "justify-center w-full"
            )}>
              <Shield className="h-3 w-3" />
              {!isCollapsed && (
                <span>
                  Report Types
                  <span className="ml-1.5 font-normal text-muted-foreground/70">({sortedReportTypes.length})</span>
                </span>
              )}
            </label>
          </div>

          {!isCollapsed && (
            <div className="mb-2">
              {sortedReportTypes.length > 8 ? (
                /* When types are many (>8), provide inline search filter */
                <div className="relative">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                  <input
                    type="text"
                    className="h-8 w-full rounded-lg border bg-background/80 pl-8 pr-7 text-xs outline-none focus:ring-1 focus:ring-primary/50 transition-shadow"
                    placeholder="Quick search types..."
                    value={typeFilterQuery}
                    onChange={(e) => setTypeFilterQuery(e.target.value)}
                  />
                  {typeFilterQuery && (
                    <button
                      onClick={() => setTypeFilterQuery("")}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  )}
                </div>
              ) : (
                /* Compact jump combobox if user prefers dropdown navigation */
                <Combobox
                  options={reportTypeOptions}
                  value={selectedType}
                  onValueChange={onSelectType}
                  placeholder="Jump to type..."
                />
              )}
            </div>
          )}

          {/* Report Type List */}
          <nav className="space-y-1">
            {filteredReportTypes.map((type) => {
              const displayName = formatReportTypeName(type.kind || type.name)
              const count = reportCounts[type.name]
              const isSelected = selectedType === type.name
              const IconComponent = getReportTypeIcon(type.kind || type.name)
              const iconColor = getReportTypeIconColor(type.kind || type.name, isSelected)

              return (
                <button
                  key={type.name}
                  onClick={() => {
                    onSelectType?.(type.name)
                    setIsMobileOpen(false)
                  }}
                  className={cn(
                    "flex w-full items-center gap-2.5 rounded-xl px-2.5 py-2 text-xs transition-all duration-150",
                    isCollapsed && "justify-center px-1.5",
                    isSelected
                      ? "bg-gradient-to-r from-primary to-primary/85 text-primary-foreground shadow-sm shadow-primary/20 font-medium"
                      : "hover:bg-muted/70 text-foreground/80 hover:text-foreground"
                  )}
                  title={isCollapsed ? `${displayName}${count !== undefined ? ` (${count})` : ""}` : undefined}
                >
                  <div className={cn(
                    "p-1.5 rounded-lg flex-shrink-0 transition-colors",
                    isSelected ? "bg-white/20" : "bg-muted"
                  )}>
                    <IconComponent className={cn("h-3.5 w-3.5", iconColor)} />
                  </div>
                  {!isCollapsed && (
                    <>
                      <span className="flex-1 text-left truncate">{displayName}</span>
                      {count !== undefined && count > 0 && (
                        <span className={cn(
                          "flex-shrink-0 rounded-full px-1.5 py-0.2 min-w-[20px] text-center text-[10px] font-semibold",
                          isSelected
                            ? "bg-white/20 text-primary-foreground"
                            : "bg-primary/10 text-primary"
                        )}>
                          {count > 99 ? "99+" : count}
                        </span>
                      )}
                      {!type.namespaced && (
                        <span className={cn(
                          "text-[9px] font-semibold px-1 py-0.2 rounded uppercase",
                          isSelected
                            ? "bg-white/20 text-primary-foreground"
                            : "bg-muted text-muted-foreground/80"
                        )}>
                          Cluster
                        </span>
                      )}
                    </>
                  )}
                </button>
              )
            })}
            {filteredReportTypes.length === 0 && (
              <p className="px-2 py-3 text-center text-xs text-muted-foreground">No matching report types</p>
            )}
          </nav>
        </div>
      </div>

      {/* Footer */}
      <div className="border-t p-3">
        <div className={cn(
          "flex items-center gap-2 text-xs text-muted-foreground",
          isCollapsed && "justify-center"
        )}>
          <div className="flex items-center gap-1.5" title={`${syncStateConfig.text}${selectedCluster ? ` (${selectedCluster})` : ""}`}>
            <span className={cn("w-2 h-2 rounded-full flex-shrink-0", syncStateConfig.color)} />
            {!isCollapsed && <span className="truncate">{syncStateConfig.text}</span>}
          </div>
          {!isCollapsed && !isSingleClusterMode && (
            <>
              <span className="text-muted-foreground/40">•</span>
              <span className="truncate">{clusters.length} clusters</span>
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
      <div
        style={{ width: isCollapsed ? 64 : sidebarWidth }}
        className={cn(
          "hidden md:flex h-screen flex-col border-r bg-card/80 backdrop-blur-sm relative",
          !isResizing && "transition-[width] duration-200"
        )}
      >
        {sidebarContent}

        {/* Drag handle for resizing sidebar */}
        {!isCollapsed && (
          <div
            onMouseDown={handleMouseDown}
            onDoubleClick={handleResetWidth}
            className={cn(
              "absolute right-0 top-0 bottom-0 w-1.5 cursor-col-resize hover:bg-primary/50 transition-colors z-20 group",
              isResizing && "bg-primary w-1.5"
            )}
            title="Drag to resize sidebar (double-click to reset)"
          >
            <div className="absolute top-1/2 -translate-y-1/2 right-[-6px] opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none p-0.5 rounded bg-card border shadow-xs">
              <GripVertical className="h-3 w-3 text-muted-foreground" />
            </div>
          </div>
        )}
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

