import { useState, useEffect } from "react"
import { useParams, useNavigate } from "react-router-dom"
import { Sidebar } from "./ui/sidebar"
import { Button } from "./ui/button"
import { ReportsList } from "./ReportsList"
import { ReportDetails } from "./ReportDetails"
import { api, type Report, type ReportType, type Cluster } from "../api/client"

const STORAGE_KEY_CLUSTER = "trivy-ui-selected-cluster"
const STORAGE_KEY_TYPE = "trivy-ui-selected-type"

export function Dashboard() {
  const params = useParams<{ cluster?: string; type?: string; namespace?: string; reportName?: string }>()
  const navigate = useNavigate()

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

    if (params.cluster) {
      setSelectedCluster(params.cluster)
    } else if (savedCluster) {
      setSelectedCluster(savedCluster)
    }

    if (params.type) {
      setSelectedType(params.type)
    } else if (savedType) {
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
        if (params.cluster && clustersData.some((c) => c.name === params.cluster)) {
          setSelectedCluster(params.cluster)
        } else if (savedCluster && clustersData.some((c) => c.name === savedCluster)) {
          setSelectedCluster(savedCluster)
        } else if (!selectedCluster) {
          setSelectedCluster(clustersData[0].name)
        }
      }

      if (typesData.length > 0) {
        if (params.type && typesData.some((t) => t.name === params.type)) {
          setSelectedType(params.type)
        } else if (savedType && typesData.some((t) => t.name === savedType)) {
          setSelectedType(savedType)
        } else if (!selectedType) {
          setSelectedType(typesData[0].name)
        }
      }

      const clusterToUse = params.cluster || savedCluster || clustersData[0]?.name
      if (clusterToUse) {
        fetchReportCounts(typesData, clusterToUse)
      }

      if (params.reportName && params.type) {
        const report: Report = {
          type: params.type,
          cluster: params.cluster || clusterToUse || "",
          namespace: params.namespace || "",
          name: params.reportName,
          data: null,
        }
        setSelectedReport(report)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error")
    } finally {
      setLoading(false)
    }
  }

  const handleSelectReport = (report: Report) => {
    setSelectedReport(report)
    const url = report.namespace
      ? `/${report.cluster}/${report.type}/${report.namespace}/${report.name}`
      : `/${report.cluster}/${report.type}/${report.name}`
    navigate(url)
  }

  const handleCloseReportDetails = () => {
    setSelectedReport(null)
    if (selectedCluster && selectedType) {
      navigate(`/${selectedCluster}/${selectedType}`)
    } else {
      navigate("/")
    }
  }

  const handleSelectCluster = (cluster: string) => {
    setSelectedCluster(cluster)
    if (selectedType) {
      navigate(`/${cluster}/${selectedType}`)
    }
  }

  const handleSelectType = (type: string) => {
    setSelectedType(type)
    if (selectedCluster) {
      navigate(`/${selectedCluster}/${type}`)
    }
  }

  const fetchReportCounts = async (types: ReportType[], cluster?: string) => {
    if (!cluster) return

    const counts: Record<string, number> = {}
    await Promise.all(
      types.map(async (type) => {
        try {
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
        onSelectCluster={handleSelectCluster}
        onSelectType={handleSelectType}
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
          cluster={selectedReport.cluster}
          namespace={selectedReport.namespace}
          onClose={handleCloseReportDetails}
        />
      )}
    </div>
  )
}
