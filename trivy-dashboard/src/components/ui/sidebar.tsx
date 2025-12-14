import { LayoutDashboard, FileText } from "lucide-react"
import { cn } from "@/lib/utils"
import { Combobox } from "./combobox"
import type { Cluster, ReportType } from "../../api/client"

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
  const clusterOptions = clusters.map((c) => ({ value: c.name, label: c.name }))
  
  const reportTypeOptions = reportTypes.map((t) => ({
    value: t.name,
    label: formatTypeName(t.kind || t.name),
  }))

  return (
    <div className="flex h-screen w-64 flex-col border-r bg-card">
      <div className="flex h-16 items-center border-b px-6">
        <LayoutDashboard className="mr-2 h-6 w-6" />
        <h1 className="text-lg font-semibold">Trivy UI</h1>
      </div>
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        <div>
          <label className="mb-2 block text-sm font-medium text-muted-foreground">
            Cluster
          </label>
          <Combobox
            options={clusterOptions}
            value={selectedCluster}
            onValueChange={onSelectCluster}
            placeholder="Select cluster..."
          />
        </div>
        <div>
          <label className="mb-2 block text-sm font-medium text-muted-foreground">
            Report Type
          </label>
          <Combobox
            options={reportTypeOptions}
            value={selectedType}
            onValueChange={onSelectType}
            placeholder="Select report type..."
          />
          <nav className="mt-2 space-y-1">
            {reportTypes
              .sort((a, b) => {
                if (a.namespaced && !b.namespaced) return -1
                if (!a.namespaced && b.namespaced) return 1
                return 0
              })
              .map((type) => {
                const displayName = formatTypeName(type.kind || type.name)
                return (
                  <button
                    key={type.name}
                    onClick={() => onSelectType?.(type.name)}
                    className={cn(
                      "flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm transition-colors",
                      selectedType === type.name
                        ? "bg-primary text-primary-foreground"
                        : "hover:bg-accent hover:text-accent-foreground"
                    )}
                  >
                    <FileText className="h-4 w-4 flex-shrink-0" />
                    <span className="flex-1 text-left truncate">{displayName}</span>
                    {reportCounts[type.name] !== undefined && reportCounts[type.name] > 0 && (
                      <span className={cn(
                        "flex-shrink-0 rounded-full px-1.5 py-0.5 min-w-[20px] text-center text-xs font-semibold",
                        selectedType === type.name
                          ? "bg-primary-foreground/20 text-primary-foreground"
                          : "bg-muted text-muted-foreground"
                      )}>
                        {reportCounts[type.name] > 99 ? "99+" : reportCounts[type.name]}
                      </span>
                    )}
                    {!type.namespaced && (
                      <span className="text-xs opacity-70 flex-shrink-0 ml-1">Cluster</span>
                    )}
                  </button>
                )
              })}
          </nav>
        </div>
      </div>
    </div>
  )
}
