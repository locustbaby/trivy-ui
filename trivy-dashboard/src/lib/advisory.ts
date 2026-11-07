import { parseSafeUrl } from "./severity"

export interface AdvisoryLink {
  label: string
  url: string
}

// Labelled links for a vulnerability ID, plus the scanner's primary link.
export function advisoryLinks(id: string, primaryLink?: string): AdvisoryLink[] {
  const links: AdvisoryLink[] = []
  const upper = id.toUpperCase()
  if (upper.startsWith("CVE-")) {
    links.push({ label: "NVD", url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(upper)}` })
    links.push({ label: "AVD", url: `https://avd.aquasec.com/nvd/${encodeURIComponent(id.toLowerCase())}` })
  } else if (upper.startsWith("GHSA-")) {
    links.push({ label: "GitHub", url: `https://github.com/advisories/${encodeURIComponent(id)}` })
  } else if (upper.startsWith("GO-")) {
    links.push({ label: "Go", url: `https://pkg.go.dev/vuln/${encodeURIComponent(upper)}` })
  } else if (upper.startsWith("DLA-") || upper.startsWith("DSA-")) {
    links.push({ label: "Debian", url: `https://security-tracker.debian.org/tracker/${encodeURIComponent(upper)}` })
  }
  const primary = primaryLink ? parseSafeUrl(primaryLink) : null
  if (primary && !links.some((link) => link.url === primary.href)) {
    links.push({ label: primary.hostname.replace(/^www\./, ""), url: primary.href })
  }
  return links
}
