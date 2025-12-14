import * as React from "react"
import { Check, ChevronsUpDown, X } from "lucide-react"
import { cn } from "@/lib/utils"
import { Button } from "./button"

interface MultiComboboxProps {
  options: { value: string; label: string }[]
  value?: string[]
  onValueChange?: (value: string[]) => void
  placeholder?: string
  className?: string
}

export function MultiCombobox({
  options,
  value = [],
  onValueChange,
  placeholder = "Select...",
  className,
}: MultiComboboxProps) {
  const [open, setOpen] = React.useState(false)
  const [inputValue, setInputValue] = React.useState("")
  const [filteredOptions, setFilteredOptions] = React.useState(options)

  React.useEffect(() => {
    if (inputValue === "") {
      setFilteredOptions(options)
    } else {
      setFilteredOptions(
        options.filter((option) =>
          option.label.toLowerCase().includes(inputValue.toLowerCase())
        )
      )
    }
  }, [inputValue, options])

  const selectedOptions = options.filter((opt) => value.includes(opt.value))

  const handleToggle = (optionValue: string) => {
    if (optionValue === "all") {
      if (value.includes("all")) {
        onValueChange?.([])
      } else {
        onValueChange?.(["all"])
      }
    } else {
      const newValue = value.includes(optionValue)
        ? value.filter((v) => v !== optionValue && v !== "all")
        : [...value.filter((v) => v !== "all"), optionValue]
      if (newValue.length === options.length - 1) {
        onValueChange?.(["all"])
      } else {
        onValueChange?.(newValue)
      }
    }
  }

  const handleRemove = (optionValue: string, e: React.MouseEvent) => {
    e.stopPropagation()
    const newValue = value.filter((v) => v !== optionValue)
    onValueChange?.(newValue)
  }

  return (
    <div className={cn("relative", className)}>
      <Button
        variant="outline"
        role="combobox"
        aria-expanded={open}
        className="w-full justify-between min-h-10 h-auto py-2"
        onClick={() => setOpen(!open)}
      >
        <div className="flex flex-wrap gap-1 flex-1 text-left">
          {selectedOptions.length === 0 ? (
            <span className="text-muted-foreground">{placeholder}</span>
          ) : (
            selectedOptions.map((option) => (
              <span
                key={option.value}
                className="inline-flex items-center gap-1 rounded-md bg-primary/10 px-2 py-0.5 text-xs"
              >
                {option.label}
                <span
                  onClick={(e) => handleRemove(option.value, e)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault()
                      handleRemove(option.value, e as any)
                    }
                  }}
                  role="button"
                  tabIndex={0}
                  className="hover:bg-primary/20 rounded-full p-0.5 cursor-pointer focus:outline-none focus:ring-2 focus:ring-ring"
                >
                  <X className="h-3 w-3" />
                </span>
              </span>
            ))
          )}
        </div>
        <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
      </Button>
      {open && (
        <>
          <div
            className="fixed inset-0 z-40"
            onClick={() => setOpen(false)}
          />
          <div className="absolute z-50 mt-1 w-full rounded-md border bg-card p-1 shadow-md">
            <input
              type="text"
              className="w-full rounded-md border px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
              placeholder="Search..."
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Escape") {
                  setOpen(false)
                  setInputValue("")
                }
              }}
            />
            <div className="max-h-60 overflow-auto">
              {filteredOptions.length === 0 ? (
                <div className="px-2 py-1.5 text-sm text-muted-foreground">
                  No results found.
                </div>
              ) : (
                filteredOptions.map((option) => {
                  const isSelected = value.includes(option.value)
                  return (
                    <button
                      key={option.value}
                      className={cn(
                        "relative flex w-full cursor-pointer select-none items-center rounded-sm px-2 py-1.5 text-sm outline-none hover:bg-accent hover:text-accent-foreground",
                        isSelected && "bg-accent"
                      )}
                      onClick={() => handleToggle(option.value)}
                    >
                      <Check
                        className={cn(
                          "mr-2 h-4 w-4",
                          isSelected ? "opacity-100" : "opacity-0"
                        )}
                      />
                      {option.label}
                    </button>
                  )
                })
              )}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
