import { ref, computed, watch } from 'vue'
import { fetchNamespaces, fetchVulnerabilityReports, fetchReportDetails } from '../api/trivy'

// Storage key constants
const NAMESPACE_STORAGE_KEY = 'trivy-selected-namespace'
const REPORTS_CACHE_PREFIX = 'trivy-reports-'
const CACHE_EXPIRATION_KEY = 'trivy-cache-expiration'

// Cache expiration time (in milliseconds) - 5 minutes
const CACHE_EXPIRATION_TIME = 5 * 60 * 1000

export function useTrivyData() {
  const loading = ref(false)
  const error = ref(null)
  const namespaces = ref([])
  
  // Try to get the last selected namespace from localStorage
  const storedNamespace = localStorage.getItem(NAMESPACE_STORAGE_KEY)
  const selectedNamespace = ref(storedNamespace || null)
  
  const vulnerabilityReports = ref([])
  const reportDetails = ref(null)
  const showReportDetails = ref(false)

  const namespaceOptions = computed(() => {
    return namespaces.value.map(ns => ({ label: ns.metadata.name, value: ns.metadata.name }))
  })

  // Save selected namespace to localStorage when it changes
  watch(selectedNamespace, (newValue) => {
    if (newValue) {
      localStorage.setItem(NAMESPACE_STORAGE_KEY, newValue)
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

  async function loadNamespaces() {
    try {
      loading.value = true
      error.value = null
      
      // Check if we have cached namespaces and if the cache is still valid
      const cachedNamespaces = localStorage.getItem('trivy-namespaces')
      if (cachedNamespaces && !isCacheExpired()) {
        namespaces.value = JSON.parse(cachedNamespaces)
      } else {
        // If no cache or expired, fetch from API
        namespaces.value = await fetchNamespaces()
        
        // Cache the namespaces
        localStorage.setItem('trivy-namespaces', JSON.stringify(namespaces.value))
        updateCacheExpiration()
      }
      
      // If we have a stored namespace, make sure it exists in the fetched namespaces
      if (selectedNamespace.value) {
        const exists = namespaces.value.some(ns => 
          ns.metadata.name === selectedNamespace.value
        )
        
        if (!exists && namespaces.value.length > 0) {
          selectedNamespace.value = namespaces.value[0].metadata.name
        }
      } else if (namespaces.value.length > 0) {
        selectedNamespace.value = namespaces.value[0].metadata.name
      }
    } catch (err) {
      error.value = `Failed to fetch namespaces: ${err.message}`
      console.error(err)
    } finally {
      loading.value = false
    }
  }

  async function loadVulnerabilityReports() {
    if (!selectedNamespace.value) return
    
    try {
      loading.value = true
      error.value = null
      
      const cacheKey = `${REPORTS_CACHE_PREFIX}${selectedNamespace.value}`
      
      // Check if we have cached reports for this namespace and if cache is valid
      const cachedReports = localStorage.getItem(cacheKey)
      if (cachedReports && !isCacheExpired()) {
        vulnerabilityReports.value = JSON.parse(cachedReports)
      } else {
        // If no cache or expired, fetch from API
        vulnerabilityReports.value = await fetchVulnerabilityReports(selectedNamespace.value)
        
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
      
      const cacheKey = `trivy-report-details-${report.metadata.namespace}-${report.metadata.name}`
      
      // Check if we have this report's details cached
      const cachedDetails = localStorage.getItem(cacheKey)
      if (cachedDetails && !isCacheExpired()) {
        reportDetails.value = JSON.parse(cachedDetails)
      } else {
        // If not cached or expired, fetch from API
        reportDetails.value = await fetchReportDetails(report.metadata.namespace, report.metadata.name)
        
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
    selectedNamespace,
    namespaceOptions,
    vulnerabilityReports,
    reportDetails,
    showReportDetails,
    loadNamespaces,
    loadVulnerabilityReports,
    loadReportDetails,
    clearCache,
    setSelectedNamespace: (namespace) => { selectedNamespace.value = namespace },
    closeReportDetails: () => { showReportDetails.value = false }
  }
}