import { BrowserRouter, Routes, Route } from "react-router-dom"
import { Dashboard } from "./components/Dashboard"
import "./App.css"

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/:cluster" element={<Dashboard />} />
        <Route path="/:cluster/:type" element={<Dashboard />} />
        <Route path="/:cluster/:type/:namespace/:reportName" element={<Dashboard />} />
        <Route path="/:cluster/:type/:reportName" element={<Dashboard />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
