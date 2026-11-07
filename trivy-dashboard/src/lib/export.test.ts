import { describe, expect, it } from "vitest"
import { toCSV } from "./export"

describe("toCSV", () => {
  it("writes a header and one line per row in column order", () => {
    expect(toCSV([{ id: "CVE-1", severity: "high" }], ["severity", "id"])).toBe("severity,id\nhigh,CVE-1\n")
  })

  it("quotes commas, quotes and newlines", () => {
    expect(toCSV([{ title: 'a, "b"\nc' }], ["title"])).toBe('title\n"a, ""b""\nc"\n')
  })

  it("neutralises spreadsheet formulas", () => {
    expect(toCSV([{ v: "=HYPERLINK(1)" }, { v: "+1" }, { v: "-1" }, { v: "@x" }], ["v"])).toBe("v\n'=HYPERLINK(1)\n'+1\n'-1\n'@x\n")
  })

  it("leaves missing values empty", () => {
    expect(toCSV([{ a: undefined, b: null }], ["a", "b", "c"])).toBe("a,b,c\n,,\n")
  })
})
