import { useSyncExternalStore } from "react"
import { dismissToast, getToasts, subscribeToasts, type Toast } from "../lib/toast"
import { cn } from "../lib/utils"

const KIND_STYLES: Record<Toast["kind"], string> = {
  error: "border-destructive/40 bg-destructive/10 text-destructive",
  info: "border-border bg-muted text-foreground",
  success: "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
}

const KIND_ICONS: Record<Toast["kind"], string> = {
  error: "✕",
  info: "ℹ",
  success: "✓",
}

export function ToastHost() {
  const toasts = useSyncExternalStore(subscribeToasts, getToasts)
  if (toasts.length === 0) return null

  return (
    <div
      aria-live="assertive"
      aria-atomic="false"
      className="fixed bottom-4 right-4 z-[100] flex w-full max-w-sm flex-col gap-2 px-2"
    >
      {toasts.map((t) => (
        <button
          key={t.id}
          type="button"
          onClick={() => dismissToast(t.id)}
          className={cn(
            "pointer-events-auto flex items-start gap-2 rounded-md border p-3 text-left text-sm shadow-lg",
            "animate-in fade-in slide-in-from-bottom-2",
            KIND_STYLES[t.kind],
          )}
        >
          <span aria-hidden className="mt-0.5 font-semibold">
            {KIND_ICONS[t.kind]}
          </span>
          <span className="flex-1 break-words">{t.message}</span>
        </button>
      ))}
    </div>
  )
}
