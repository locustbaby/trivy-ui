import { useState, useCallback } from "react"
import { Check, Copy } from "lucide-react"
import type { Report } from "../../api/client"

interface ReportInfoCardProps {
  report: Report
  imageRef: string | null
  artifact: any
  scanner: any
  hasVulnerabilitiesType: boolean
}

export function ReportInfoCard({
  report,
  imageRef,
  artifact,
  scanner,
  hasVulnerabilitiesType,
}: ReportInfoCardProps) {
  const [copiedField, setCopiedField] = useState<string | null>(null)

  const copyToClipboard = useCallback((text: string, fieldId: string) => {
    navigator.clipboard
      .writeText(text)
      .then(() => {
        setCopiedField(fieldId)
        setTimeout(() => setCopiedField(null), 1500)
      })
      .catch((err) => {
        console.error("Failed to copy:", err)
      })
  }, [])

  const CopyableField = ({ value, fieldId, className = "" }: { value: string; fieldId: string; className?: string }) => (
    <button
      onClick={() => copyToClipboard(value, fieldId)}
      className={`group inline-flex items-center gap-1.5 hover:text-primary transition-colors cursor-pointer text-left ${className}`}
      title="Click to copy"
    >
      <span className={copiedField === fieldId ? "text-green-500" : ""}>{value}</span>
      {copiedField === fieldId ? (
        <Check className="h-3.5 w-3.5 text-green-500 flex-shrink-0" />
      ) : (
        <Copy className="h-3.5 w-3.5 opacity-0 group-hover:opacity-50 flex-shrink-0" />
      )}
    </button>
  )

  return (
    <div className="rounded-lg border bg-gradient-to-br from-card to-muted/20 p-3">
      <div className="flex flex-wrap gap-x-6 gap-y-2 text-sm">
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-muted-foreground">Name:</span>
          <CopyableField value={report.name} fieldId="name" className="font-semibold" />
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-muted-foreground">Cluster:</span>
          <CopyableField value={report.cluster} fieldId="cluster" />
        </div>
        {report.namespace && (
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-muted-foreground">Namespace:</span>
            <CopyableField value={report.namespace} fieldId="namespace" />
          </div>
        )}
        {report.updated_at && (
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-muted-foreground">Updated:</span>
            <span>{new Date(report.updated_at).toLocaleString()}</span>
          </div>
        )}
        {hasVulnerabilitiesType && scanner && scanner.name && (
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-muted-foreground">Scanner:</span>
            <span className="font-medium">{scanner.name}{scanner.version ? ` v${scanner.version}` : ''}</span>
          </div>
        )}
      </div>

      {imageRef && (
        <div className="mt-2 pt-2 border-t">
          <button
            onClick={() => copyToClipboard(imageRef, "image")}
            className="group w-full text-left text-xs font-mono break-all bg-muted/50 hover:bg-muted rounded px-2 py-1.5 transition-colors cursor-pointer flex items-center justify-between gap-2"
            title="Click to copy"
          >
            <span className={copiedField === "image" ? "text-green-500" : ""}>{imageRef}</span>
            {copiedField === "image" ? (
              <Check className="h-3.5 w-3.5 text-green-500 flex-shrink-0" />
            ) : (
              <Copy className="h-3.5 w-3.5 opacity-0 group-hover:opacity-50 flex-shrink-0" />
            )}
          </button>
        </div>
      )}

      {hasVulnerabilitiesType && artifact && artifact.digest && (
        <div className="mt-1.5">
          <button
            onClick={() => copyToClipboard(artifact.digest, "digest")}
            className="group w-full text-left text-xs font-mono break-all bg-muted/50 hover:bg-muted rounded px-2 py-1.5 transition-colors cursor-pointer flex items-center justify-between gap-2"
            title="Click to copy"
          >
            <span className={copiedField === "digest" ? "text-green-500" : ""}>{artifact.digest}</span>
            {copiedField === "digest" ? (
              <Check className="h-3.5 w-3.5 text-green-500 flex-shrink-0" />
            ) : (
              <Copy className="h-3.5 w-3.5 opacity-0 group-hover:opacity-50 flex-shrink-0" />
            )}
          </button>
        </div>
      )}
    </div>
  )
}
