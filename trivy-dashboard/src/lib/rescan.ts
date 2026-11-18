import { useEffect, useState } from "react"
import { api, type RescanState, type RescanStatus } from "../api/client"

// Loaded once per signed-in user; resetRescanCapabilities() runs on login and
// logout so a different user on the same page gets their own permissions.
let capabilities: Promise<RescanStatus | null> | null = null

export function resetRescanCapabilities() {
  capabilities = null
}

function loadCapabilities(): Promise<RescanStatus | null> {
  if (!capabilities) {
    capabilities = api.getRescanStatus().catch(() => {
      capabilities = null
      return null
    })
  }
  return capabilities
}

export interface RescanCapabilities {
  allowed: boolean
  types: string[]
  maxBulk: number
}

const NONE: RescanCapabilities = { allowed: false, types: [], maxBulk: 0 }

export function useRescanCapabilities(): RescanCapabilities {
  const [value, setValue] = useState<RescanCapabilities>(NONE)
  useEffect(() => {
    let active = true
    void loadCapabilities().then((status) => {
      if (active && status?.enabled && status.allowed) {
        setValue({ allowed: true, types: status.types, maxBulk: status.maxBulk })
      }
    })
    return () => {
      active = false
    }
  }, [])
  return value
}

export function canRescanType(capabilities: RescanCapabilities, typeName: string): boolean {
  return capabilities.allowed && capabilities.types.includes(typeName.toLowerCase())
}

export function describeRescan(state: RescanState): string {
  const since = new Date(state.requestedAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  return `Rescanning since ${since}${state.requestedBy ? ` (requested by ${state.requestedBy})` : ""}`
}

export const RESCAN_POLL_INTERVAL = 10000
