export type Severity = "critical" | "high" | "medium" | "low" | "unknown"

export function getSeverityColor(severity: string): string {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "text-red-600 dark:text-red-400"
    case "high":
      return "text-orange-600 dark:text-orange-400"
    case "medium":
      return "text-yellow-600 dark:text-yellow-400"
    case "low":
      return "text-blue-600 dark:text-blue-400"
    default:
      return "text-gray-600 dark:text-gray-400"
  }
}

export function getSeverityBgColor(severity: string): string {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "bg-red-50 dark:bg-red-950/30 border-red-200 dark:border-red-900/50"
    case "high":
      return "bg-orange-50 dark:bg-orange-950/30 border-orange-200 dark:border-orange-900/50"
    case "medium":
      return "bg-yellow-50 dark:bg-yellow-950/30 border-yellow-200 dark:border-yellow-900/50"
    case "low":
      return "bg-blue-50 dark:bg-blue-950/30 border-blue-200 dark:border-blue-900/50"
    default:
      return "bg-gray-50 dark:bg-gray-900/30 border-gray-200 dark:border-gray-800"
  }
}

export function getSeverityBadgeColor(severity: string): string {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "bg-red-100 dark:bg-red-900/50 text-red-700 dark:text-red-300"
    case "high":
      return "bg-orange-100 dark:bg-orange-900/50 text-orange-700 dark:text-orange-300"
    case "medium":
      return "bg-yellow-100 dark:bg-yellow-900/50 text-yellow-700 dark:text-yellow-300"
    case "low":
      return "bg-blue-100 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300"
    default:
      return "bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300"
  }
}

export function getSeverityDotColor(severity: string): string {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "bg-red-500"
    case "high":
      return "bg-orange-500"
    case "medium":
      return "bg-yellow-500"
    case "low":
      return "bg-blue-500"
    default:
      return "bg-gray-500"
  }
}

export function parseSafeUrl(url: string): { hostname: string } | null {
  try {
    return new URL(url)
  } catch {
    return null
  }
}

export interface SeverityCounts {
  critical: number
  high: number
  medium: number
  low: number
}

export function hasSeverityIssues(counts: SeverityCounts | null): boolean {
  if (!counts) return false
  return counts.critical > 0 || counts.high > 0 || counts.medium > 0 || counts.low > 0
}
