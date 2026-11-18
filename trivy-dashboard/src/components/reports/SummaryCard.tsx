interface SummaryCardProps {
  summary: {
    criticalCount?: number
    highCount?: number
    mediumCount?: number
    lowCount?: number
    unknownCount?: number
    noneCount?: number
  }
  // Findings with a fixed version, when the report lists vulnerabilities.
  fixable?: number
}

export function SummaryCard({ summary, fixable }: SummaryCardProps) {
  const hasAnyCount =
    (summary.criticalCount ?? 0) > 0 ||
    (summary.highCount ?? 0) > 0 ||
    (summary.mediumCount ?? 0) > 0 ||
    (summary.lowCount ?? 0) > 0 ||
    (summary.unknownCount ?? 0) > 0 ||
    (summary.noneCount ?? 0) > 0

  if (!hasAnyCount) {
    return null
  }

  return (
    <div className="rounded-lg border bg-card p-3">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-sm font-medium text-muted-foreground">Summary:</span>
        {(summary.criticalCount ?? 0) > 0 && (
          <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-red-50 dark:bg-red-950/30">
            <span className="w-2 h-2 rounded-full bg-red-500 severity-pulse" />
            <span className="text-sm font-bold text-red-600 dark:text-red-400">{summary.criticalCount}</span>
            <span className="text-xs text-muted-foreground">Critical</span>
          </div>
        )}
        {(summary.highCount ?? 0) > 0 && (
          <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-orange-50 dark:bg-orange-950/30">
            <span className="w-2 h-2 rounded-full bg-orange-500" />
            <span className="text-sm font-bold text-orange-600 dark:text-orange-400">{summary.highCount}</span>
            <span className="text-xs text-muted-foreground">High</span>
          </div>
        )}
        {(summary.mediumCount ?? 0) > 0 && (
          <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-yellow-50 dark:bg-yellow-950/30">
            <span className="w-2 h-2 rounded-full bg-yellow-500" />
            <span className="text-sm font-bold text-yellow-600 dark:text-yellow-400">{summary.mediumCount}</span>
            <span className="text-xs text-muted-foreground">Medium</span>
          </div>
        )}
        {(summary.lowCount ?? 0) > 0 && (
          <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-blue-50 dark:bg-blue-950/30">
            <span className="w-2 h-2 rounded-full bg-blue-500" />
            <span className="text-sm font-bold text-blue-600 dark:text-blue-400">{summary.lowCount}</span>
            <span className="text-xs text-muted-foreground">Low</span>
          </div>
        )}
        {(summary.unknownCount ?? 0) > 0 && (
          <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-slate-100 dark:bg-slate-800/50" title="No severity assigned yet">
            <span className="w-2 h-2 rounded-full bg-slate-400" />
            <span className="text-sm font-bold text-slate-600 dark:text-slate-300">{summary.unknownCount}</span>
            <span className="text-xs text-muted-foreground">Unknown</span>
          </div>
        )}
        {fixable !== undefined && (
          <span className="text-xs text-muted-foreground" title="Findings with a fixed version available">
            {fixable} fixable
          </span>
        )}
        {(summary.noneCount ?? 0) > 0 && (
          <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-green-50 dark:bg-green-950/30">
            <span className="w-2 h-2 rounded-full bg-green-500" />
            <span className="text-sm font-bold text-green-600 dark:text-green-400">{summary.noneCount}</span>
            <span className="text-xs text-muted-foreground">None</span>
          </div>
        )}
      </div>
    </div>
  )
}
