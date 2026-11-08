import { lazy, type ComponentType } from "react"

const RELOAD_KEY = "trivy-ui:chunk-reload"

// After a deploy, an open page still references the previous build's chunk
// names, which no longer exist. Reload once to fetch the current index.html;
// the session flag prevents a reload loop if the chunk is really broken.
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- same constraint as React.lazy
export function lazyWithReload<T extends ComponentType<any>>(load: () => Promise<{ default: T }>) {
  return lazy(async () => {
    try {
      const module = await load()
      sessionStorage.removeItem(RELOAD_KEY)
      return module
    } catch (error) {
      if (!sessionStorage.getItem(RELOAD_KEY)) {
        sessionStorage.setItem(RELOAD_KEY, "1")
        window.location.reload()
        return new Promise<never>(() => {})
      }
      throw error
    }
  })
}
