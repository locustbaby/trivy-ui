import { describe, expect, it } from "vitest"
import type { TrendRecord } from "../api/client"
import { vulnerabilityTrend } from "./trends"

const record = (timestamp: string, kind?: string): TrendRecord => ({ timestamp, cluster: "", kind, critical: 1, high: 2, medium: 3 })

describe("vulnerabilityTrend", () => {
  it("uses vulnerability-only records and notes hidden older ones", () => {
    const series = vulnerabilityTrend([record("2026-11-01T00:00:00Z"), record("2026-11-07T10:00:00Z", "vulnerabilities"), record("2026-11-07T11:00:00Z", "vulnerabilities")])
    expect(series.legacy).toBe(false)
    expect(series.records).toHaveLength(2)
    expect(series.hiddenBefore?.toISOString()).toBe("2026-11-07T10:00:00.000Z")
  })

  it("keeps older data until two new points exist", () => {
    const series = vulnerabilityTrend([record("2026-11-01T00:00:00Z"), record("2026-11-07T10:00:00Z", "vulnerabilities")])
    expect(series.legacy).toBe(true)
    expect(series.records).toHaveLength(1)
  })

  it("handles new installs without older data", () => {
    const series = vulnerabilityTrend([record("2026-11-07T10:00:00Z", "vulnerabilities")])
    expect(series.legacy).toBe(false)
    expect(series.hiddenBefore).toBeUndefined()
  })
})
