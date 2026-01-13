interface SummaryCardProps {
  summary: {
    criticalCount?: number
    highCount?: number
    mediumCount?: number
    lowCount?: number
    noneCount?: number
  }
}

export function SummaryCard({ summary }: SummaryCardProps) {
  const hasAnyCount =
    (summary.criticalCount ?? 0) > 0 ||
    (summary.highCount ?? 0) > 0 ||
    (summary.mediumCount ?? 0) > 0 ||
    (summary.lowCount ?? 0) > 0 ||
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
