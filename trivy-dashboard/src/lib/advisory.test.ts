import { describe, expect, it } from "vitest"
import { advisoryLinks } from "./advisory"

describe("advisoryLinks", () => {
  it("links CVEs to NVD and AVD", () => {
    expect(advisoryLinks("CVE-2026-1234").map((l) => l.label)).toEqual(["NVD", "AVD"])
    expect(advisoryLinks("cve-2026-1234")[0].url).toBe("https://nvd.nist.gov/vuln/detail/CVE-2026-1234")
  })

  it("knows GitHub, Go and Debian advisories", () => {
    expect(advisoryLinks("GHSA-abcd-1234-efgh")[0].url).toBe("https://github.com/advisories/GHSA-abcd-1234-efgh")
    expect(advisoryLinks("GO-2026-4918")[0].url).toBe("https://pkg.go.dev/vuln/GO-2026-4918")
    expect(advisoryLinks("DLA-1234-1")[0].label).toBe("Debian")
  })

  it("adds the scanner link once and drops unsafe ones", () => {
    expect(advisoryLinks("CVE-1", "https://avd.aquasec.com/nvd/cve-1")).toHaveLength(2)
    expect(advisoryLinks("TEMP-1", "javascript:alert(1)")).toEqual([])
    expect(advisoryLinks("TEMP-1", "https://www.example.org/x")).toEqual([{ label: "example.org", url: "https://www.example.org/x" }])
  })
})
