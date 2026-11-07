import type { TrendRecord } from "../api/client"

export interface TrendSeries {
  records: TrendRecord[]
  // Older records added up every report type; they are only shown when no
  // vulnerability-only records exist yet.
  legacy: boolean
  // First vulnerability-only point, when older mixed records were left out.
  hiddenBefore?: Date
}

export function vulnerabilityTrend(records: TrendRecord[]): TrendSeries {
  const current = records.filter((record) => record.kind === "vulnerabilities")
  if (current.length === 0) {
    return { records, legacy: records.length > 0 }
  }
  const hasLegacy = records.some((record) => !record.kind)
  return {
    records: current,
    legacy: false,
    hiddenBefore: hasLegacy ? new Date(current[0].timestamp) : undefined,
  }
}

export function formatTrendLabel(timestamp: string, days: number): string {
  const d = new Date(timestamp)
  const date = `${d.getMonth() + 1}/${d.getDate()}`
  return days <= 7 ? `${date} ${String(d.getHours()).padStart(2, "0")}:00` : date
}
