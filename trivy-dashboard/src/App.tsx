import { useCallback, useEffect, useState } from "react"
import { Dashboard } from "./components/Dashboard"
import { ErrorBoundary } from "./components/ErrorBoundary"
import { LoginPage } from "./components/LoginPage"
import { api, ApiError } from "./api/client"
import { invalidateCached } from "./lib/apiCache"
import { toast } from "./lib/toast"
import { CustomErrorPage } from "./components/CustomErrorPage"
import { ToastHost } from "./components/ToastHost"
import "./App.css"

function App() {
  const [state, setState] = useState<"loading" | "login" | "ready" | "unavailable">("loading")
  const [username, setUsername] = useState<string>()

  const checkAuth = useCallback(async () => {
    try {
      const auth = await api.getAuthMe()
      setUsername(auth.username)
      setState(auth.mode === "none" || auth.authenticated ? "ready" : "login")
    } catch (err) {
      setState(err instanceof ApiError && err.status === 503 ? "unavailable" : "login")
    }
  }, [])

  useEffect(() => {
    void Promise.resolve().then(checkAuth)
  }, [checkAuth])

  useEffect(() => {
    const handleAuthExpired = () => {
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
  }, [])

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
      <Dashboard username={username} onLogout={() => { invalidateCached(); api.logout().finally(() => { setUsername(undefined); setState("login") }) }} />
      <ToastHost />
    </ErrorBoundary>
  )
}

export default App
