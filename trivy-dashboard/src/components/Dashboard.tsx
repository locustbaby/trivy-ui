import { useState, useEffect } from "react"
import { Sidebar } from "./ui/sidebar"
import { Button } from "./ui/button"
import { ReportsList } from "./ReportsList"
import { ReportDetails } from "./ReportDetails"
import { api, type Report, type ReportType, type Cluster } from "../api/client"

const STORAGE_KEY_CLUSTER = "trivy-ui-selected-cluster"
const STORAGE_KEY_TYPE = "trivy-ui-selected-type"

export function Dashboard() {
  const [clusters, setClusters] = useState<Cluster[]>([])
  const [reportTypes, setReportTypes] = useState<ReportType[]>([])
  const [reportCounts, setReportCounts] = useState<Record<string, number>>({})
  const [selectedCluster, setSelectedCluster] = useState<string>()
  const [selectedType, setSelectedType] = useState<string>()
  const [selectedReport, setSelectedReport] = useState<Report | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>()

  useEffect(() => {
    const savedCluster = localStorage.getItem(STORAGE_KEY_CLUSTER)
    const savedType = localStorage.getItem(STORAGE_KEY_TYPE)
    if (savedCluster) {
      setSelectedCluster(savedCluster)
    }
    if (savedType) {
      setSelectedType(savedType)
    }
    fetchData()
  }, [])

  useEffect(() => {
    if (selectedCluster) {
      localStorage.setItem(STORAGE_KEY_CLUSTER, selectedCluster)
    }
  }, [selectedCluster])

  useEffect(() => {
    if (selectedType) {
      localStorage.setItem(STORAGE_KEY_TYPE, selectedType)
    }
  }, [selectedType])

  const fetchData = async () => {
    try {
      setLoading(true)
      const [clustersData, typesData] = await Promise.all([
        api.getClusters(),
        api.getTypes(),
      ])
      setClusters(clustersData)
      setReportTypes(typesData)
      
      const savedCluster = localStorage.getItem(STORAGE_KEY_CLUSTER)
      const savedType = localStorage.getItem(STORAGE_KEY_TYPE)
      
      if (clustersData.length > 0) {
        if (savedCluster && clustersData.some((c) => c.name === savedCluster)) {
          setSelectedCluster(savedCluster)
        } else if (!selectedCluster) {
          setSelectedCluster(clustersData[0].name)
        }
      }
      
      if (typesData.length > 0) {
        if (savedType && typesData.some((t) => t.name === savedType)) {
          setSelectedType(savedType)
        } else if (!selectedType) {
          setSelectedType(typesData[0].name)
        }
      }

      const clusterToUse = savedCluster || clustersData[0]?.name
      if (clusterToUse) {
        fetchReportCounts(typesData, clusterToUse)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error")
    } finally {
      setLoading(false)
    }
  }

  const handleSelectReport = (report: Report) => {
    setSelectedReport(report)
  }

  const handleCloseReportDetails = () => {
    setSelectedReport(null)
  }

  const fetchReportCounts = async (types: ReportType[], cluster?: string) => {
    if (!cluster) return
    
    const counts: Record<string, number> = {}
    await Promise.all(
      types.map(async (type) => {
        try {
          // For cluster-scoped reports, don't pass namespace parameter
          const response = await api.getReportsByType(type.name, 1, 1, cluster, undefined)
          counts[type.name] = response.total
        } catch (err) {
          counts[type.name] = 0
        }
      })
    )
    setReportCounts(counts)
  }

  useEffect(() => {
    if (selectedCluster && reportTypes.length > 0) {
      fetchReportCounts(reportTypes, selectedCluster)
    }
  }, [selectedCluster, reportTypes])

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="text-destructive">Error: {error}</div>
        <Button onClick={fetchData} className="ml-4">
          Retry
        </Button>
      </div>
    )
  }

  return (
    <div className="flex h-screen">
      <Sidebar
        clusters={clusters}
        reportTypes={reportTypes}
        reportCounts={reportCounts}
        selectedCluster={selectedCluster}
        selectedType={selectedType}
        onSelectCluster={setSelectedCluster}
        onSelectType={setSelectedType}
      />
      <main className="flex-1 overflow-y-auto p-8">
        <div className="mx-auto max-w-7xl">
          <h1 className="mb-6 text-3xl font-bold">Dashboard</h1>
          {selectedType ? (
            <ReportsList
              typeName={selectedType}
              reportTypes={reportTypes}
              selectedCluster={selectedCluster}
              onSelectReport={handleSelectReport}
            />
          ) : (
            <div className="rounded-lg border bg-card p-6">
              <p className="text-muted-foreground">Please select a report type from the sidebar</p>
            </div>
          )}
        </div>
      </main>
      {selectedReport && (
        <ReportDetails
          typeName={selectedReport.type}
          reportName={selectedReport.name}
          onClose={handleCloseReportDetails}
        />
      )}
    </div>
  )
}
