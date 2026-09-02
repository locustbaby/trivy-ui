/**
 * Tiny TTL cache for metadata endpoints (clusters, report types).
 *
 * Used to make cluster switching instant: when a cached entry is still fresh
 * the UI hydrates from it immediately while a background request revalidates.
 * Keep every TTL well below the dashboard polling intervals (30s metadata /
 * 15s counts) so polling always hits the network and stays authoritative.
 */

interface CacheEntry {
  value: unknown
  fetchedAt: number
}

const store = new Map<string, CacheEntry>()

export function getCachedFresh<T>(key: string, maxAgeMs: number): T | undefined {
  const entry = store.get(key)
  if (!entry) return undefined
  if (Date.now() - entry.fetchedAt > maxAgeMs) {
    store.delete(key)
    return undefined
  }
  return entry.value as T
}

export function setCached(key: string, value: unknown): void {
  if (value === undefined) {
    store.delete(key)
    return
  }
  store.set(key, { value, fetchedAt: Date.now() })
}

export function invalidateCached(prefix?: string): void {
  if (!prefix) {
    store.clear()
    return
  }
  for (const key of store.keys()) {
    if (key.startsWith(prefix)) store.delete(key)
  }
}
