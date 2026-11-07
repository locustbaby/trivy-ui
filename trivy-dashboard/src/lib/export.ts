// Client-side CSV/JSON downloads of what is currently shown.

function download(content: string, filename: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }))
  const link = document.createElement("a")
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

function csvCell(value: unknown): string {
  const text = value === undefined || value === null ? "" : String(value)
  // Leading =,+,-,@ would be evaluated as formulas by spreadsheet programs.
  const safe = /^[=+\-@]/.test(text) ? `'${text}` : text
  return /[",\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe
}

export function toCSV(rows: Record<string, unknown>[], columns: string[]): string {
  const lines = [columns.join(","), ...rows.map((row) => columns.map((column) => csvCell(row[column])).join(","))]
  return lines.join("\n") + "\n"
}

export function downloadCSV(rows: Record<string, unknown>[], columns: string[], filename: string) {
  download(toCSV(rows, columns), filename, "text/csv;charset=utf-8")
}

export function downloadJSON(data: unknown, filename: string) {
  download(JSON.stringify(data, null, 2), filename, "application/json")
}

export function exportFilename(base: string, extension: string): string {
  return `${base}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.${extension}`
}
