import { ref, computed, watch } from 'vue'
import { fetchNamespaces, fetchReports, fetchReportDetails } from '../api/trivy'
import { useClusterData } from './useClusterData'
import { isClusterLevelReport } from '../utils/reportTypeUtils'

// Storage key constants
const NAMESPACE_STORAGE_KEY = 'trivy-selected-namespace'
const CLUSTER_STORAGE_KEY = 'trivy-selected-cluster'
const REPORTS_CACHE_PREFIX = 'trivy-reports-'
const CACHE_EXPIRATION_KEY = 'trivy-cache-expiration'

// Cache expiration time (in milliseconds) - 30 minutes (matching backend)
const CACHE_EXPIRATION_TIME = 30 * 60 * 1000

export function useTrivyData(reportType = 'vulnerability') {
  const loading = ref(false)
  const error = ref(null)
  const namespaces = ref([])
  const reports = ref([])

  // Try to get the last selected namespace and cluster from localStorage
  const storedNamespace = localStorage.getItem(NAMESPACE_STORAGE_KEY)
  const storedCluster = localStorage.getItem(CLUSTER_STORAGE_KEY)
  const selectedNamespace = ref(storedNamespace || null)
  const selectedCluster = ref(storedCluster || null)

  const reportDetails = ref(null)
  const showReportDetails = ref(false)
  const currentReportType = ref('vulnerabilityreports')
  const searchQuery = ref('')

  // Get enabled clusters
  const { enabledClusters } = useClusterData()

  const namespaceOptions = computed(() => {
    return namespaces.value.map(ns => ({
      label: ns,
      value: ns
    }))
  })

  // Save selected namespace and cluster to localStorage when they change
  watch(selectedNamespace, (newValue) => {
    if (newValue) {
      localStorage.setItem(NAMESPACE_STORAGE_KEY, newValue)
    }
  })

  watch(selectedCluster, (newValue) => {
    if (newValue) {
      localStorage.setItem(CLUSTER_STORAGE_KEY, newValue)
    }
  })

  // Watch for changes in enabled clusters
  watch(enabledClusters, () => {
    // If the selected cluster is disabled, reset it and clear reports
    if (selectedCluster.value && !enabledClusters.value.some(c => c.name === selectedCluster.value)) {
      selectedCluster.value = null
      selectedNamespace.value = null
      namespaces.value = []
      reports.value = []
      // Clear any stored data
      localStorage.removeItem(CLUSTER_STORAGE_KEY)
      localStorage.removeItem(NAMESPACE_STORAGE_KEY)
    }
  })

  // Listen for cluster status change events
  if (typeof window !== 'undefined') {
    window.addEventListener('cluster-status-changed', (event) => {
      const { clusterName, enabled } = event.detail

      // If the cluster was enabled, select it and reload namespaces
      if (enabled) {
        selectedCluster.value = clusterName
        loadNamespaces().then(() => {
          if (selectedNamespace.value) {
            return loadReports()
          }
        }).catch(err => {
          console.error('Error reloading data after cluster enabled:', err)
        })
      } else {
        // If the cluster was disabled, clear reports if it was selected
        if (selectedCluster.value === clusterName) {
          selectedCluster.value = null
          selectedNamespace.value = null
          namespaces.value = []
          reports.value = []
          // Clear any stored data
          localStorage.removeItem(CLUSTER_STORAGE_KEY)
          localStorage.removeItem(NAMESPACE_STORAGE_KEY)
        }
      }
    })
  }

  // Check if cache is expired
  function isCacheExpired() {
    const expiration = localStorage.getItem(CACHE_EXPIRATION_KEY)
    if (!expiration) return true
    return Date.now() > parseInt(expiration, 10)
  }

  // Set cache expiration time
  function updateCacheExpiration() {
    localStorage.setItem(CACHE_EXPIRATION_KEY, Date.now() + CACHE_EXPIRATION_TIME)
  }

  // Get cache key for reports
  function getReportsCacheKey() {
    // For cluster-level reports, don't include namespace in the cache key
    if (isClusterLevelReport(currentReportType.value)) {
      return `${REPORTS_CACHE_PREFIX}${currentReportType.value}-${selectedCluster.value}`
    }
    // For namespace-level reports, include namespace in the cache key
    return `${REPORTS_CACHE_PREFIX}${currentReportType.value}-${selectedCluster.value}-${selectedNamespace.value}`
  }

  async function loadNamespaces() {
    try {
      loading.value = true
      error.value = null

      // Only load namespaces if a cluster is selected
      if (!selectedCluster.value) {
        namespaces.value = []
        return
      }

      // Check if we have cached namespaces and if the cache is still valid
      const cachedNamespaces = localStorage.getItem(`trivy-namespaces-${selectedCluster.value}`)

      if (cachedNamespaces && !isCacheExpired()) {
        namespaces.value = JSON.parse(cachedNamespaces)
      } else {
        // If no cache or expired, fetch from API
        const fetchedNamespaces = await fetchNamespaces(selectedCluster.value)

        // Ensure we have an array of namespace names
        namespaces.value = Array.isArray(fetchedNamespaces) ? fetchedNamespaces : []

        // Cache the namespaces
        localStorage.setItem(`trivy-namespaces-${selectedCluster.value}`, JSON.stringify(namespaces.value))
        updateCacheExpiration()
      }
    } catch (err) {
      error.value = `Failed to fetch namespaces: ${err.message}`
      console.error('Error loading namespaces:', err)
    } finally {
      loading.value = false
    }
  }

  // Check if the current report type is a cluster-level report

  const loadReports = async (refresh = false) => {
    // For cluster-level reports, we only need the cluster to be selected
    // For namespace-level reports, we need both cluster and namespace
    const isClusterLevel = isClusterLevelReport(currentReportType.value)

    if (!selectedCluster.value || (!isClusterLevel && !selectedNamespace.value)) {
      reports.value = []
      return
    }

    loading.value = true
    error.value = null

    try {
      // Check if we have cached reports and if the cache is still valid
      const cacheKey = getReportsCacheKey()
      const cachedReports = localStorage.getItem(cacheKey)

      // If we have valid cached reports, use them immediately
      if (cachedReports) {
        reports.value = JSON.parse(cachedReports)
        loading.value = false

        // If cache is expired or refresh is requested, fetch new data in the background
        if (isCacheExpired() || refresh) {
          // Don't set loading to true to avoid UI flicker
          backgroundRefresh(refresh)
          return
        }
        return
      }

      // No cached data, fetch from API (backend will handle getting from DB or Kubernetes)
      // Always set refresh=true on first load to ensure we get data if DB is empty
      const shouldRefresh = refresh || !cachedReports
      // For cluster-level reports, pass empty namespace
      const namespace = isClusterLevel ? '' : selectedNamespace.value
      const response = await fetchReports(currentReportType.value, selectedCluster.value, namespace, shouldRefresh)

      if (response?.data?.reports && Array.isArray(response.data.reports)) {
        // Transform all reports data
        reports.value = response.data.reports.map(report => {
          const transformedReport = {
            ...report,
            cluster: report.cluster || report.data?.metadata?.labels?.['trivy-operator.cluster'] || 'N/A',
            metadata: report.data?.metadata || {},
            report: report.data?.report || {},
            // Ensure data field is preserved for resource information
            data: report.data || {}
          }
          return transformedReport
        })

        // Cache the reports with error handling
        try {
          // Create a simplified version of the reports to reduce storage size
          const simplifiedReports = reports.value.map(report => ({
            name: report.name,
            cluster: report.cluster,
            namespace: report.namespace,
            metadata: {
              name: report.metadata?.name,
              namespace: report.metadata?.namespace,
              creationTimestamp: report.metadata?.creationTimestamp,
              labels: report.metadata?.labels
            },
            // Include data.metadata.labels for resource information
            data: {
              metadata: {
                labels: report.data?.metadata?.labels || {}
              }
            },
            report: {
              summary: report.report?.summary || {}
              // Exclude full vulnerability details to save space
            }
          }))

          localStorage.setItem(cacheKey, JSON.stringify(simplifiedReports))
          updateCacheExpiration()
        } catch (err) {
          console.warn('Failed to cache reports:', err.message)
          // If storage quota is exceeded, clear old caches to make room
          if (err.name === 'QuotaExceededError' ||
              err.message.includes('exceeded the quota') ||
              err.message.includes('quota_exceeded')) {
            console.log('Storage quota exceeded, clearing old caches')
            clearOldCaches()
          }
        }
      } else {
        reports.value = []
      }
    } catch (err) {
      console.error('Error loading reports:', err)
      error.value = err.message || 'Failed to load reports'
      reports.value = []
    } finally {
      loading.value = false
    }
  }

  function handleClusterChange(cluster) {
    // If cluster is null or undefined, clear everything
    if (!cluster) {
      selectedCluster.value = null
      selectedNamespace.value = null
      namespaces.value = []
      reports.value = []
      return
    }

    // Update selected cluster
    selectedCluster.value = cluster

    // Check if this is a cluster-level report
    const isClusterLevel = isClusterLevelReport(currentReportType.value)

    // For cluster-level reports, we can load reports directly without loading namespaces
    if (isClusterLevel) {
      loadReports()
      return
    }

    // For namespace-level reports, load namespaces first
    loadNamespaces().then(() => {
      // If we have namespaces, select the first one if none is selected
      if (namespaces.value.length > 0) {
        if (!selectedNamespace.value || !namespaces.value.includes(selectedNamespace.value)) {
          selectedNamespace.value = namespaces.value[0]
        }

        // Now load reports since we have both cluster and namespace
        loadReports()
      } else {
        selectedNamespace.value = null
        reports.value = []
      }
    }).catch(err => {
      console.error('Error loading data after cluster change:', err)
      error.value = `Failed to load data: ${err.message}`
    })
  }

  function handleNamespaceChange(namespace) {
    // Only update namespace for namespace-level reports
    if (!isClusterLevelReport(currentReportType.value)) {
      selectedNamespace.value = namespace

      // Load reports for the new namespace
      if (selectedCluster.value && namespace) {
        loadReports()
      } else {
        reports.value = []
      }
    }
  }

  function handleSearch(query) {
    searchQuery.value = query
  }

  function setReportType(type) {
    // Map the report type to the correct API value
    const apiReportType = type === 'vulnerability' ? 'vulnerabilityreports' : type
    currentReportType.value = apiReportType
    loadReports()
  }

  // Background refresh function to update data without blocking UI
  async function backgroundRefresh(forceRefresh = false) {
    try {
      console.log('Performing background refresh...')
      // Check if this is a cluster-level report
      const isClusterLevel = isClusterLevelReport(currentReportType.value)

      // For namespace-level reports, we need both cluster and namespace
      // For cluster-level reports, we only need the cluster
      if (!isClusterLevel && !selectedNamespace.value) {
        console.log('No namespace selected for namespace-level report, skipping refresh')
        return
      }

      // Fetch new data from API
      const response = await fetchReports(
        currentReportType.value,
        selectedCluster.value,
        isClusterLevel ? '' : selectedNamespace.value, // Empty namespace for cluster-level reports
        forceRefresh
      )

      if (response?.data?.reports && Array.isArray(response.data.reports)) {
        // Transform all reports data
        const newReports = response.data.reports.map(report => {
          const transformedReport = {
            ...report,
            cluster: report.cluster || report.data?.metadata?.labels?.['trivy-operator.cluster'] || 'N/A',
            metadata: report.data?.metadata || {},
            report: report.data?.report || {},
            // Ensure data field is preserved for resource information
            data: report.data || {}
          }
          return transformedReport
        })

        // Update reports if data has changed
        if (JSON.stringify(newReports) !== JSON.stringify(reports.value)) {
          reports.value = newReports

          // Cache the reports with error handling
          try {
            const cacheKey = getReportsCacheKey()

            // Create a simplified version of the reports to reduce storage size
            const simplifiedReports = newReports.map(report => ({
              name: report.name,
              cluster: report.cluster,
              namespace: report.namespace,
              metadata: {
                name: report.metadata?.name,
                namespace: report.metadata?.namespace,
                creationTimestamp: report.metadata?.creationTimestamp,
                labels: report.metadata?.labels
              },
              // Include data.metadata.labels for resource information
              data: {
                metadata: {
                  labels: report.data?.metadata?.labels || {}
                }
              },
              report: {
                summary: report.report?.summary || {}
                // Exclude full vulnerability details to save space
              }
            }))

            localStorage.setItem(cacheKey, JSON.stringify(simplifiedReports))
            updateCacheExpiration()
          } catch (err) {
            console.warn('Failed to cache reports in background refresh:', err.message)
            // If storage quota is exceeded, clear old caches to make room
            if (err.name === 'QuotaExceededError' ||
                err.message.includes('exceeded the quota') ||
                err.message.includes('quota_exceeded')) {
              console.log('Storage quota exceeded, clearing old caches')
              clearOldCaches()
            }
          }

          console.log('Background refresh completed with new data')
        } else {
          console.log('Background refresh completed, no changes')
        }
      }
    } catch (err) {
      console.error('Error in background refresh:', err)
      // Don't update error.value to avoid UI disruption
    }
  }

  // Clear all caches
  function clearCache() {
    // Clear all report caches
    Object.keys(localStorage).forEach(key => {
      if (key.startsWith(REPORTS_CACHE_PREFIX)) {
        localStorage.removeItem(key)
      }
    })

    // Clear namespace caches
    Object.keys(localStorage).forEach(key => {
      if (key.startsWith('trivy-namespaces-')) {
        localStorage.removeItem(key)
      }
    })

    // Clear cache expiration
    localStorage.removeItem(CACHE_EXPIRATION_KEY)
  }

  // Clear old caches to make room for new data
  function clearOldCaches() {
    try {
      // Get all cache keys
      const cacheKeys = Object.keys(localStorage).filter(key =>
        key.startsWith(REPORTS_CACHE_PREFIX) && key !== getReportsCacheKey()
      )

      // If we have other caches, remove them
      if (cacheKeys.length > 0) {
        console.log(`Clearing ${cacheKeys.length} old caches to make room`)
        cacheKeys.forEach(key => localStorage.removeItem(key))
        return true
      }

      // If we don't have other caches, clear the current cache
      console.log('No old caches to clear, clearing current cache')
      localStorage.removeItem(getReportsCacheKey())
      return true
    } catch (err) {
      console.error('Error clearing old caches:', err)
      return false
    }
  }

  return {
    loading,
    error,
    reports,
    namespaces,
    selectedCluster,
    selectedNamespace,
    searchQuery,
    reportDetails,
    showReportDetails,
    namespaceOptions,
    loadReports,
    loadNamespaces,
    handleClusterChange,
    handleNamespaceChange,
    handleSearch,
    setReportType,
    clearCache,
    currentReportType
  }
}