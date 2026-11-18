import { useCallback, useEffect, useState } from "react"
import { Dashboard } from "./components/Dashboard"
import { ErrorBoundary } from "./components/ErrorBoundary"
import { LoginPage } from "./components/LoginPage"
import { api, ApiError } from "./api/client"
import { invalidateCached } from "./lib/apiCache"
import { resetRescanCapabilities } from "./lib/rescan"
import { toast } from "./lib/toast"
import { CustomErrorPage } from "./components/CustomErrorPage"
import { ToastHost } from "./components/ToastHost"
import "./App.css"

function App() {
  const [state, setState] = useState<"loading" | "login" | "ready" | "unavailable" | "proxy-signed-out">("loading")
  const [username, setUsername] = useState<string>()
  const [proxyMode, setProxyMode] = useState(false)

  const checkAuth = useCallback(async () => {
    resetRescanCapabilities()
    try {
      const auth = await api.getAuthMe()
      setUsername(auth.username)
      setProxyMode(auth.mode === "proxy")
      if (auth.mode === "none" || auth.authenticated) {
        setState("ready")
      } else {
        setState(auth.mode === "proxy" ? "proxy-signed-out" : "login")
      }
    } catch (err) {
      setState(err instanceof ApiError && err.status === 503 ? "unavailable" : "login")
    }
  }, [])

  useEffect(() => {
    void Promise.resolve().then(checkAuth)
  }, [checkAuth])

  useEffect(() => {
    const handleAuthExpired = () => {
      if (proxyMode) {
        // The authenticating proxy signs the user in again on a full page load.
        window.location.reload()
        return
      }
      setUsername(undefined)
      setState("login")
      toast("Your session has expired. Please sign in again.", "info")
    }
    const handleAccessDenied = () => {
      toast("You do not have permission to access this resource.", "error")
    }
    const handleServiceUnavailable = () => {
      toast("The server is temporarily unavailable. Retrying may help.", "error")
    }
    window.addEventListener("trivy-ui:auth-expired", handleAuthExpired)
    window.addEventListener("trivy-ui:access-denied", handleAccessDenied)
    window.addEventListener("trivy-ui:service-unavailable", handleServiceUnavailable)
    return () => {
      window.removeEventListener("trivy-ui:auth-expired", handleAuthExpired)
      window.removeEventListener("trivy-ui:access-denied", handleAccessDenied)
      window.removeEventListener("trivy-ui:service-unavailable", handleServiceUnavailable)
    }
  }, [proxyMode])

  if (state === "loading") {
    return (
      <>
        <div className="flex min-h-screen items-center justify-center text-muted-foreground">Loading...</div>
        <ToastHost />
      </>
    )
  }
  if (state === "login") {
    return (
      <>
        <LoginPage onLogin={checkAuth} />
        <ToastHost />
      </>
    )
  }
  if (state === "proxy-signed-out") {
    return (
      <CustomErrorPage>
        <div className="flex min-h-screen flex-col items-center justify-center gap-3 text-muted-foreground">
          <p>You are not signed in. Sign-in is handled by the authenticating proxy.</p>
          <button className="underline" onClick={() => window.location.reload()}>Reload to sign in</button>
        </div>
        <ToastHost />
      </CustomErrorPage>
    )
  }
  if (state === "unavailable") {
    return (
      <CustomErrorPage>
        <div className="flex min-h-screen items-center justify-center text-destructive">Authentication service is unavailable. Please try again later.</div>
        <ToastHost />
      </CustomErrorPage>
    )
  }

  return (
    <ErrorBoundary>
      <Dashboard
        username={username}
        onLogout={proxyMode ? undefined : () => { invalidateCached(); resetRescanCapabilities(); api.logout().finally(() => { setUsername(undefined); setState("login") }) }}
      />
      <ToastHost />
    </ErrorBoundary>
  )
}

export default App
