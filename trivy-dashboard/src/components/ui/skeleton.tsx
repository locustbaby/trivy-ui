import { cn } from "@/lib/utils"

interface SkeletonProps {
  className?: string
}

export function Skeleton({ className }: SkeletonProps) {
  return (
    <div
      className={cn(
        "animate-pulse rounded-md bg-muted",
        className
      )}
    />
  )
}

export function ReportCardSkeleton() {
  return (
    <div className="rounded-xl border bg-card p-4">
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 mb-3">
            <Skeleton className="h-5 w-48" />
            <Skeleton className="h-5 w-16 rounded-full" />
            <Skeleton className="h-5 w-16 rounded-full" />
          </div>
          <div className="flex flex-wrap gap-4">
            <Skeleton className="h-4 w-24" />
            <Skeleton className="h-4 w-32" />
            <Skeleton className="h-4 w-40" />
          </div>
        </div>
        <Skeleton className="h-8 w-8 rounded-lg" />
      </div>
    </div>
  )
}

export function ReportsListSkeleton({ count = 5 }: { count?: number }) {
  return (
    <div className="space-y-6">
      {/* Header skeleton */}
      <div className="flex items-center justify-between">
        <div>
          <Skeleton className="h-8 w-32 mb-2" />
          <Skeleton className="h-4 w-48" />
        </div>
        <Skeleton className="h-9 w-24" />
      </div>

      {/* Filters skeleton */}
      <div className="flex gap-4 items-end flex-wrap">
        <div className="w-64">
          <Skeleton className="h-4 w-20 mb-2" />
          <Skeleton className="h-10 w-full" />
        </div>
        <div className="flex-1 min-w-[200px]">
          <Skeleton className="h-4 w-16 mb-2" />
          <Skeleton className="h-10 w-full" />
        </div>
        <Skeleton className="h-11 w-40" />
      </div>

      {/* Reports skeleton */}
      <div className="grid gap-3">
        {Array.from({ length: count }).map((_, i) => (
          <ReportCardSkeleton key={i} />
        ))}
      </div>
    </div>
  )
}

export function ReportDetailsSkeleton() {
  return (
    <div className="space-y-4">
      {/* Info card skeleton */}
      <div className="rounded-xl border bg-card p-5">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {[1, 2, 3].map((i) => (
            <div key={i}>
              <Skeleton className="h-3 w-16 mb-2" />
              <Skeleton className="h-5 w-full" />
            </div>
          ))}
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-5 mt-5 pt-5 border-t">
          {[1, 2, 3].map((i) => (
            <div key={i}>
              <Skeleton className="h-3 w-20 mb-2" />
              <Skeleton className="h-5 w-24" />
            </div>
          ))}
        </div>
      </div>

      {/* Summary skeleton */}
      <div className="rounded-xl border bg-card p-5">
        <Skeleton className="h-6 w-24 mb-4" />
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="flex items-center gap-3 p-3 rounded-lg bg-muted/30">
              <Skeleton className="w-3 h-3 rounded-full" />
              <div>
                <Skeleton className="h-8 w-12 mb-1" />
                <Skeleton className="h-3 w-16" />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Vulnerabilities skeleton */}
      <div className="rounded-xl border bg-card p-5">
        <Skeleton className="h-6 w-32 mb-4" />
        <div className="flex gap-3 mb-4">
          <Skeleton className="h-9 flex-1" />
          <div className="flex gap-1">
            {[1, 2, 3, 4, 5].map((i) => (
              <Skeleton key={i} className="h-9 w-16" />
            ))}
          </div>
        </div>
        <div className="space-y-2">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-24 w-full rounded-lg" />
          ))}
        </div>
      </div>
    </div>
  )
}
