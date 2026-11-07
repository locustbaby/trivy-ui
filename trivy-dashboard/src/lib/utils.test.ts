import { afterEach, describe, expect, it, vi } from "vitest"
import { reportTypeLabel, scanAge } from "./utils"

describe("reportTypeLabel", () => {
  it("names known report types", () => {
    expect(reportTypeLabel("clusterrbacassessmentreports")).toBe("Cluster RBAC Assessment")
    expect(reportTypeLabel("vulnerabilityreports")).toBe("Vulnerability")
  })
})

describe("scanAge", () => {
  afterEach(() => vi.useRealTimers())

  it("describes the age and flags scans older than three days", () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date("2026-11-07T12:00:00Z"))
    expect(scanAge("2026-11-07T11:30:00Z")).toEqual({ label: "less than an hour ago", stale: false })
    expect(scanAge("2026-11-07T02:00:00Z")).toEqual({ label: "10 h ago", stale: false })
    expect(scanAge("2026-11-03T12:00:00Z")).toEqual({ label: "4 days ago", stale: true })
    expect(scanAge(undefined)).toBeNull()
    expect(scanAge("not a date")).toBeNull()
  })
})
