import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatReportTypeName(name: string): string {
  let formatted = name.replace(/Report$/i, "")
  formatted = formatted.replace(/([a-z])([A-Z])/g, "$1 $2")
  formatted = formatted.replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
  return formatted.trim()
}

const REPORT_TYPE_LABELS: Record<string, string> = {
  vulnerabilityreports: "Vulnerability",
  clustervulnerabilityreports: "Cluster Vulnerability",
  configauditreports: "Config Audit",
  clusterconfigauditreports: "Cluster Config Audit",
  exposedsecretreports: "Exposed Secret",
  rbacassessmentreports: "RBAC Assessment",
  clusterrbacassessmentreports: "Cluster RBAC Assessment",
  infraassessmentreports: "Infra Assessment",
  clusterinfraassessmentreports: "Cluster Infra Assessment",
  clustercompliancereports: "Compliance",
  sbomreports: "SBOM",
  clustersbomreports: "Cluster SBOM",
}

// Readable name for a report type given as its plural resource name.
export function reportTypeLabel(name: string): string {
  return REPORT_TYPE_LABELS[name.toLowerCase()] ?? formatReportTypeName(name)
}

// Scans older than this are flagged: the operator rescans every 24 h.
export const SCAN_STALE_HOURS = 72

export function scanAge(timestamp?: string): { label: string; stale: boolean } | null {
  if (!timestamp) return null
  const scanned = new Date(timestamp).getTime()
  if (Number.isNaN(scanned)) return null
  const hours = (Date.now() - scanned) / 3_600_000
  const label = hours < 1 ? "less than an hour ago" : hours < 48 ? `${Math.floor(hours)} h ago` : `${Math.floor(hours / 24)} days ago`
  return { label, stale: hours > SCAN_STALE_HOURS }
}
