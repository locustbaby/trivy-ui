import { Dashboard } from "./components/Dashboard"
import { ErrorBoundary } from "./components/ErrorBoundary"
import "./App.css"

function App() {
  return (
    <ErrorBoundary>
      <Dashboard />
    </ErrorBoundary>
  )
}

export default App
