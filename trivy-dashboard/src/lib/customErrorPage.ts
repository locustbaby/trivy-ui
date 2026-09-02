import { useEffect, useState } from "react"
import { API_BASE_URL } from "../api/client"

/**
 * Loader/hook for the operator-configured custom error page.
 *
 * Two channels, checked in order:
 *  1. ERROR_PAGE_CONFIG (structured: title/message/contact items) served as
 *     JSON from /api/v1/error-page — rendered natively by the UI.
 *  2. ERROR_PAGE_FILE (raw operator-provided HTML) served at
 *     /error-page.html — rendered with the same trust level as the app
 *     bundle itself; never point it at user-writable storage.
 *
 * When neither is configured, hooks resolve to `undefined` and callers fall
 * back to their built-in error UI.
 */

export interface ErrorPageItem {
  type: "email" | "link"
  label: string
  value: string
}

export interface ErrorPageConfig {
  title: string
  message: string
  items?: ErrorPageItem[]
}

let configPromise: Promise<ErrorPageConfig | null> | null = null
let htmlPromise: Promise<string | null> | null = null

function loadErrorPageConfig(): Promise<ErrorPageConfig | null> {
  configPromise ??= fetch(`${API_BASE_URL}/api/v1/error-page`, {
    cache: "no-store",
    credentials: "include",
  })
    .then(async (response) => {
      if (!response.ok) return null
      const body = await response.json().catch(() => null)
      const data = body?.data
      if (!data || !data.enabled) return null
      return { title: data.title, message: data.message ?? "", items: Array.isArray(data.items) ? data.items : [] }
    })
    .catch(() => null)
    .then((config) => {
      // Don't pin negative results for the whole session so late
      // configuration is picked up on the next error screen.
      if (config === null) configPromise = null
      return config
    })
  return configPromise
}

function loadCustomErrorHtml(): Promise<string | null> {
  htmlPromise ??= fetch(`${API_BASE_URL}/error-page.html`, {
    cache: "no-store",
    credentials: "include",
  })
    .then((response) => (response.ok ? response.text() : null))
    .catch(() => null)
    .then((content) => {
      if (content === null) htmlPromise = null
      return content
    })
  return htmlPromise
}

/** Test/debug helper: forces the next mount to re-fetch both channels. */
export function resetCustomErrorPageCache(): void {
  configPromise = null
  htmlPromise = null
}

/**
 * Resolves the configured error page. Returns:
 *  - `{ kind: "config", config }` when ERROR_PAGE_CONFIG is set
 *  - `{ kind: "html", html }` when only ERROR_PAGE_FILE is set
 *  - `undefined` while loading or when nothing is configured
 */
export type ResolvedErrorPage =
  | { kind: "config"; config: ErrorPageConfig }
  | { kind: "html"; html: string }
  | undefined

export function useCustomErrorPage(): ResolvedErrorPage {
  const [resolved, setResolved] = useState<ResolvedErrorPage>(undefined)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      const config = await loadErrorPageConfig()
      if (cancelled) return
      if (config) {
        setResolved({ kind: "config", config })
        return
      }
      const html = await loadCustomErrorHtml()
      if (cancelled) return
      setResolved(html ? { kind: "html", html } : undefined)
    })()
    return () => {
      cancelled = true
    }
  }, [])

  return resolved
}
