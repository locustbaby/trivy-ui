// Minimal dependency-free toast store. Components subscribe via
// subscribeToasts and render the queue; any module can raise a toast by
// calling toast() without needing access to React state.

export type ToastKind = "error" | "info" | "success"

export interface Toast {
  id: number
  kind: ToastKind
  message: string
}

const DURATION_MS = 6000

let toasts: Toast[] = []
let nextId = 1
const listeners = new Set<() => void>()
const timers = new Map<number, ReturnType<typeof setTimeout>>()

function emit() {
  for (const listener of listeners) listener()
}

export function getToasts(): Toast[] {
  return toasts
}

export function subscribeToasts(listener: () => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function dismissToast(id: number) {
  const timer = timers.get(id)
  if (timer) {
    clearTimeout(timer)
    timers.delete(id)
  }
  if (!toasts.some((t) => t.id === id)) return
  toasts = toasts.filter((t) => t.id !== id)
  emit()
}

// Raises a toast. Repeated calls with the same message while the toast is
// still visible refresh its timer instead of stacking duplicates, so polling
// code can safely report failures on every tick.
export function toast(message: string, kind: ToastKind = "error", durationMs = DURATION_MS) {
  if (!message) return
  const existing = toasts.find((t) => t.message === message && t.kind === kind)
  if (existing) {
    const timer = timers.get(existing.id)
    if (timer) clearTimeout(timer)
    timers.set(
      existing.id,
      setTimeout(() => dismissToast(existing.id), durationMs),
    )
    return
  }
  const item: Toast = { id: nextId++, kind, message }
  toasts = [...toasts, item]
  timers.set(
    item.id,
    setTimeout(() => dismissToast(item.id), durationMs),
  )
  // Keep the stack short; drop the oldest entries beyond five.
  while (toasts.length > 5) {
    dismissToast(toasts[0].id)
  }
  emit()
}
