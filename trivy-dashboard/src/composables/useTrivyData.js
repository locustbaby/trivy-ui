import { ref, computed, watch } from 'vue'
import { fetchNamespaces, fetchVulnerabilityReports, fetchReportDetails, fetchClusters } from '../api/trivy'

// Storage key constants
const NAMESPACE_STORAGE_KEY = 'trivy-selected-namespace'
const CLUSTER_STORAGE_KEY = 'trivy-selected-cluster'
const REPORTS_CACHE_PREFIX = 'trivy-reports-'
const CACHE_EXPIRATION_KEY = 'trivy-cache-expiration'

// Cache expiration time (in milliseconds) - 5 minutes
const CACHE_EXPIRATION_TIME = 5 * 60 * 1000

export function useTrivyData() {
  const loading = ref(false)
  const error = ref(null)
  const namespaces = ref([])
  const clusters = ref([])
  
  // Try to get the last selected namespace and cluster from localStorage
  const storedNamespace = localStorage.getItem(NAMESPACE_STORAGE_KEY)
  const storedCluster = localStorage.getItem(CLUSTER_STORAGE_KEY)
  const selectedNamespace = ref(storedNamespace || null)
  const selectedCluster = ref(storedCluster || null)
  
  const vulnerabilityReports = ref([])
  const reportDetails = ref(null)
  const showReportDetails = ref(false)

  const namespaceOptions = computed(() => {
    return namespaces.value.map(ns => ({ label: ns.metadata.name, value: ns.metadata.name }))
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

  async function loadClusters() {
    try {
      loading.value = true
      error.value = null
      
      // Check if we have cached clusters and if the cache is still valid
      const cachedClusters = localStorage.getItem('trivy-clusters')
      if (cachedClusters && !isCacheExpired()) {
        clusters.value = JSON.parse(cachedClusters).filter(cluster => cluster.enable)
      } else {
        // If no cache or expired, fetch from API
        const allClusters = await fetchClusters()
        // Filter enabled clusters
        clusters.value = allClusters.filter(cluster => cluster.enable)
        
        // Cache the clusters
        localStorage.setItem('trivy-clusters', JSON.stringify(allClusters))
        updateCacheExpiration()
      }
      
      // If we have a stored cluster, make sure it exists in the fetched clusters
      if (selectedCluster.value) {
        const exists = clusters.value.some(cluster => 
          cluster.name === selectedCluster.value
        )
        
        if (!exists) {
          // 如果当前选中的集群不存在或已被禁用，则选择第一个可用的集群
          if (clusters.value.length > 0) {
            selectedCluster.value = clusters.value[0].name
          } else {
            selectedCluster.value = null
          }
          
          // 触发全局事件，通知其他组件当前选中的集群已更改
          window.dispatchEvent(new CustomEvent('selected-cluster-changed', { 
            detail: { clusterName: selectedCluster.value } 
          }))
        }
      } else if (clusters.value.length > 0) {
        selectedCluster.value = clusters.value[0].name
      }
    } catch (err) {
      error.value = `Failed to fetch clusters: ${err.message}`
      console.error(err)
    } finally {
      loading.value = false
    }
  }

  async function loadNamespaces() {
    if (!selectedCluster.value) {
      console.warn('Cannot load namespaces: No cluster selected')
      namespaces.value = []
      return
    }
    
    try {
      loading.value = true
      error.value = null
      
      // 检查选中的集群是否启用
      const allClusters = JSON.parse(localStorage.getItem('trivy-clusters') || '[]')
      const selectedClusterData = allClusters.find(c => c.name === selectedCluster.value)
      
      if (!selectedClusterData || !selectedClusterData.enable) {
        error.value = `Cannot load namespaces: Cluster "${selectedCluster.value}" is disabled`
        namespaces.value = []
        return
      }
      
      // 直接从 API 获取命名空间，不使用缓存
      console.log(`Loading namespaces for cluster: ${selectedCluster.value}`)
      const fetchedNamespaces = await fetchNamespaces(selectedCluster.value)
      
      if (!fetchedNamespaces || fetchedNamespaces.length === 0) {
        console.warn(`No namespaces found for cluster: ${selectedCluster.value}`)
        namespaces.value = []
        return
      }
      
      namespaces.value = fetchedNamespaces
      
      // 缓存命名空间
      localStorage.setItem(`trivy-namespaces-${selectedCluster.value}`, JSON.stringify(namespaces.value))
      updateCacheExpiration()
      
      // 如果当前选中的命名空间不存在于新加载的命名空间中，则选择第一个可用的命名空间
      if (selectedNamespace.value) {
        const exists = namespaces.value.some(ns => 
          ns.metadata.name === selectedNamespace.value
        )
        
        if (!exists && namespaces.value.length > 0) {
          selectedNamespace.value = namespaces.value[0].metadata.name
          console.log(`Selected namespace changed to: ${selectedNamespace.value}`)
        }
      } else if (namespaces.value.length > 0) {
        selectedNamespace.value = namespaces.value[0].metadata.name
        console.log(`Selected namespace set to: ${selectedNamespace.value}`)
      }
    } catch (err) {
      error.value = `Failed to fetch namespaces: ${err.message}`
      console.error('Error loading namespaces:', err)
      namespaces.value = []
    } finally {
      loading.value = false
    }
  }

  async function loadVulnerabilityReports() {
    if (!selectedNamespace.value || !selectedCluster.value) return
    
    try {
      loading.value = true
      error.value = null
      
      // 检查选中的集群是否启用
      const allClusters = JSON.parse(localStorage.getItem('trivy-clusters') || '[]')
      const selectedClusterData = allClusters.find(c => c.name === selectedCluster.value)
      
      if (!selectedClusterData || !selectedClusterData.enable) {
        error.value = `Cannot load reports: Cluster "${selectedCluster.value}" is disabled`
        vulnerabilityReports.value = []
        return
      }
      
      const cacheKey = `${REPORTS_CACHE_PREFIX}${selectedCluster.value}-${selectedNamespace.value}`
      
      // Check if we have cached reports for this namespace and cluster and if cache is valid
      const cachedReports = localStorage.getItem(cacheKey)
      if (cachedReports && !isCacheExpired()) {
        vulnerabilityReports.value = JSON.parse(cachedReports)
      } else {
        // If no cache or expired, fetch from API
        vulnerabilityReports.value = await fetchVulnerabilityReports(selectedNamespace.value, selectedCluster.value)
        
        try {
          // Cache the reports - wrap in try/catch as localStorage might be full
          localStorage.setItem(cacheKey, JSON.stringify(vulnerabilityReports.value))
          updateCacheExpiration()
        } catch (storageErr) {
          console.warn('Failed to cache reports in localStorage:', storageErr)
          // Try to clear old cache entries if storage is full
          clearOldCacheEntries()
        }
      }
    } catch (err) {
      error.value = `Failed to fetch vulnerability reports: ${err.message}`
      console.error(err)
    } finally {
      loading.value = false
    }
  }

  // Clear old cache entries when storage might be full
  function clearOldCacheEntries() {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i)
      if (key.startsWith(REPORTS_CACHE_PREFIX)) {
        localStorage.removeItem(key)
      }
    }
  }

  // Clear cache manually if needed
  function clearCache() {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i)
      if (key.startsWith('trivy-')) {
        localStorage.removeItem(key)
      }
    }
  }

  async function loadReportDetails(report) {
    try {
      loading.value = true
      error.value = null
      
      // 检查选中的集群是否启用
      const allClusters = JSON.parse(localStorage.getItem('trivy-clusters') || '[]')
      const selectedClusterData = allClusters.find(c => c.name === selectedCluster.value)
      
      if (!selectedClusterData || !selectedClusterData.enable) {
        error.value = `Cannot load report details: Cluster "${selectedCluster.value}" is disabled`
        reportDetails.value = null
        showReportDetails.value = false
        return
      }
      
      const cacheKey = `trivy-report-details-${selectedCluster.value}-${report.metadata.namespace}-${report.metadata.name}`
      
      // Check if we have this report's details cached
      const cachedDetails = localStorage.getItem(cacheKey)
      if (cachedDetails && !isCacheExpired()) {
        reportDetails.value = JSON.parse(cachedDetails)
      } else {
        // If not cached or expired, fetch from API
        reportDetails.value = await fetchReportDetails(report.metadata.namespace, report.metadata.name, selectedCluster.value)
        
        try {
          // Cache the report details
          localStorage.setItem(cacheKey, JSON.stringify(reportDetails.value))
        } catch (storageErr) {
          console.warn('Failed to cache report details in localStorage:', storageErr)
        }
      }
      
      showReportDetails.value = true
    } catch (err) {
      error.value = `Failed to fetch report details: ${err.message}`
      console.error(err)
    } finally {
      loading.value = false
    }
  }

  return {
    loading,
    error,
    namespaces,
    clusters,
    selectedNamespace,
    selectedCluster,
    namespaceOptions,
    vulnerabilityReports,
    reportDetails,
    showReportDetails,
    loadNamespaces,
    loadClusters,
    loadVulnerabilityReports,
    loadReportDetails,
    clearCache,
    setSelectedNamespace: (namespace) => { selectedNamespace.value = namespace },
    setSelectedCluster: (cluster) => { selectedCluster.value = cluster },
    closeReportDetails: () => { showReportDetails.value = false }
  }
}