import type { ReactNode } from "react"
import { Mail, ExternalLink, LifeBuoy } from "lucide-react"
import { useCustomErrorPage } from "../lib/customErrorPage"

/**
 * Renders the operator-configured error page when one is set (structured
 * config preferred, raw HTML file as fallback), otherwise falls back to
 * children (the built-in error UI).
 */

export function ConfigErrorPage({ title, message, items }: { title: string; message: string; items: { type: string; label: string; value: string }[] }) {
  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-6">
      <div className="w-full max-w-lg rounded-2xl border bg-card shadow-xl p-8">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2.5 rounded-xl bg-primary/10">
            <LifeBuoy className="h-6 w-6 text-primary" />
          </div>
          <h1 className="text-xl font-semibold">{title}</h1>
        </div>
        {message && <p className="text-sm text-muted-foreground leading-relaxed mb-5">{message}</p>}
        {items.length > 0 && (
          <ul className="space-y-2.5">
            {items.map((item, index) => (
              <li key={`${item.type}-${item.value}-${index}`}>
                <a
                  href={item.type === "email" ? `mailto:${item.value}` : item.value}
                  target={item.type === "link" ? "_blank" : undefined}
                  rel={item.type === "link" ? "noopener noreferrer" : undefined}
                  className="flex items-center gap-2.5 rounded-xl border bg-background px-4 py-3 text-sm transition-colors hover:bg-muted/60 hover:border-primary/30"
                >
                  {item.type === "email" ? (
                    <Mail className="h-4 w-4 text-primary shrink-0" />
                  ) : (
                    <ExternalLink className="h-4 w-4 text-primary shrink-0" />
                  )}
                  <span className="font-medium">{item.label}</span>
                  <span className="text-muted-foreground truncate ml-auto">{item.value}</span>
                </a>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}

/** Presentational shell for a resolved raw-HTML custom page. */
export function CustomErrorPageContent({ html }: { html: string }) {
  return (
    <div className="min-h-screen bg-background flex items-start sm:items-center justify-center p-4 sm:p-8 overflow-auto">
      <div
        className="w-full max-w-2xl rounded-2xl border bg-card shadow-xl p-6 [&_a]:text-primary [&_a]:underline [&_h1]:text-2xl [&_h1]:font-semibold [&_h1]:mb-3 [&_h2]:text-lg [&_h2]:font-semibold [&_p]:text-sm [&_p]:text-muted-foreground [&_ul]:list-disc [&_ul]:pl-5 [&_li]:text-sm"
        data-custom-error-page
      >
        <div dangerouslySetInnerHTML={{ __html: html }} />
      </div>
    </div>
  )
}

interface CustomErrorPageProps {
  children: ReactNode
}

/**
 * Renders the configured error page when one is set, otherwise falls back to
 * children. While resolution is still in flight the built-in fallback is
 * shown to avoid a blank flash.
 */
export function CustomErrorPage({ children }: CustomErrorPageProps) {
  const page = useCustomErrorPage()
  if (!page) return <>{children}</>
  if (page.kind === "config") {
    return <ConfigErrorPage title={page.config.title} message={page.config.message} items={page.config.items ?? []} />
  }
  return <CustomErrorPageContent html={page.html} />
}
