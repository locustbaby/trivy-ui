import { useState, useEffect } from "react"
import type { FormEvent } from "react"
import { Shield, Loader2, Eye, EyeOff } from "lucide-react"
import { api, ApiError } from "../api/client"
import { Button } from "./ui/button"
import { ConfigErrorPage, CustomErrorPageContent } from "./CustomErrorPage"
import { useCustomErrorPage } from "../lib/customErrorPage"

interface LoginPageProps {
  onLogin: () => Promise<void>
}

const REMEMBER_USERNAME_KEY = "trivy-ui-remembered-username"

export function LoginPage({ onLogin }: LoginPageProps) {
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [showPassword, setShowPassword] = useState(false)
  const [rememberUsername, setRememberUsername] = useState(false)
  const [error, setError] = useState<string>()
  const [errorStatus, setErrorStatus] = useState<number>()
  const [loading, setLoading] = useState(false)
  const customErrorPage = useCustomErrorPage()

  useEffect(() => {
    const saved = localStorage.getItem(REMEMBER_USERNAME_KEY)
    if (saved) {
      setUsername(saved)
      setRememberUsername(true)
    }
  }, [])

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    setError(undefined)
    setLoading(true)
    try {
      if (rememberUsername) {
        localStorage.setItem(REMEMBER_USERNAME_KEY, username.trim())
      } else {
        localStorage.removeItem(REMEMBER_USERNAME_KEY)
      }
      await api.login(username, password)
      await onLogin()
    } catch (err) {
      setError(err instanceof ApiError && err.status === 503 ? "Authentication service is unavailable" : err instanceof Error ? err.message : "Login failed")
      setErrorStatus(err instanceof ApiError ? err.status : undefined)
    } finally {
      setLoading(false)
    }
  }

  if (error && errorStatus === 503 && customErrorPage) {
    // Auth service is down and the operator provides a dedicated page
    // (contacts, runbooks): take over the whole screen instead of the form,
    // but keep a way back so recovery doesn't require a manual reload.
    return (
      <div className="relative">
        {customErrorPage.kind === "config" ? (
          <ConfigErrorPage
            title={customErrorPage.config.title}
            message={customErrorPage.config.message}
            items={customErrorPage.config.items ?? []}
          />
        ) : (
          <CustomErrorPageContent html={customErrorPage.html} />
        )}
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-10">
          <Button
            variant="outline"
            size="sm"
            className="bg-card shadow-lg"
            onClick={() => {
              setError(undefined)
              setErrorStatus(undefined)
            }}
          >
            Back to sign in
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-background to-muted/50 p-6">
      <form onSubmit={submit} className="w-full max-w-sm space-y-5 rounded-2xl border bg-card p-8 shadow-xl" method="post" action="#">
        <div className="flex flex-col items-center gap-3 text-center">
          <Shield className="h-12 w-12 text-primary" />
          <div>
            <h1 className="text-2xl font-semibold">Trivy Dashboard</h1>
            <p className="text-sm text-muted-foreground">Sign in to continue</p>
          </div>
        </div>
        <div className="space-y-2">
          <label htmlFor="username" className="block text-sm font-medium">
            Username
          </label>
          <input
            id="username"
            name="username"
            type="text"
            className="h-10 w-full rounded-md border bg-background px-3 font-normal outline-none focus:ring-2 focus:ring-ring"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
            required
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck="false"
          />
        </div>
        <div className="space-y-2">
          <label htmlFor="password" className="block text-sm font-medium">
            Password
          </label>
          <div className="relative flex items-center">
            <input
              id="password"
              name="password"
              type={showPassword ? "text" : "password"}
              className="h-10 w-full rounded-md border bg-background pl-3 pr-10 font-normal outline-none focus:ring-2 focus:ring-ring"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
              required
            />
            <button
              type="button"
              className="absolute right-3 text-muted-foreground hover:text-foreground focus:outline-none"
              onClick={() => setShowPassword(!showPassword)}
              tabIndex={-1}
              title={showPassword ? "Hide password" : "Show password"}
              aria-label={showPassword ? "Hide password" : "Show password"}
            >
              {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
        </div>
        <div className="flex items-center justify-between text-sm">
          <label className="flex items-center gap-2 cursor-pointer select-none text-muted-foreground hover:text-foreground">
            <input
              type="checkbox"
              className="h-4 w-4 rounded border border-primary text-primary focus:ring-2 focus:ring-ring"
              checked={rememberUsername}
              onChange={(e) => setRememberUsername(e.target.checked)}
            />
            Remember username
          </label>
        </div>
        {error && <p className="text-sm text-destructive">{error}</p>}
        <Button type="submit" className="w-full" disabled={loading}>
          {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          Sign in
        </Button>
      </form>
    </div>
  )
}

