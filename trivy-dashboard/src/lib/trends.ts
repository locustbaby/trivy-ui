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
  const legacy = records.filter((record) => !record.kind)
  // A single new point draws no line; keep showing the older data until the
  // hourly recorder has written a second one.
  if (current.length < 2 && legacy.length > 0) {
    return { records: legacy, legacy: true }
  }
  if (current.length === 0) {
    return { records, legacy: false }
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
