import { ref, computed } from 'vue'
import { fetchClusters, addCluster, deleteCluster } from '../api/trivy'

// Storage key constants
const CLUSTERS_STORAGE_KEY = 'trivy-clusters'
const CACHE_EXPIRATION_KEY = 'trivy-cache-expiration'

// Cache expiration time (in milliseconds) - 5 minutes
const CACHE_EXPIRATION_TIME = 5 * 60 * 1000

export function useClusterData() {
  const loading = ref(false)
  const error = ref(null)
  const clusters = ref([])
  const showAddClusterModal = ref(false)

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
      const cachedClusters = localStorage.getItem(CLUSTERS_STORAGE_KEY)
      if (cachedClusters && !isCacheExpired()) {
        clusters.value = JSON.parse(cachedClusters)
      } else {
        // If no cache or expired, fetch from API
        clusters.value = await fetchClusters()
        
        // Cache the clusters
        localStorage.setItem(CLUSTERS_STORAGE_KEY, JSON.stringify(clusters.value))
        updateCacheExpiration()
      }
    } catch (err) {
      error.value = `Failed to fetch clusters: ${err.message}`
      console.error(err)
    } finally {
      loading.value = false
    }
  }

  async function createCluster(clusterData) {
    try {
      loading.value = true
      error.value = null
      
      await addCluster(clusterData)
      
      // Reload clusters to get the updated list
      await loadClusters()
      
      // Close the modal
      showAddClusterModal.value = false
      
      return true
    } catch (err) {
      error.value = `Failed to add cluster: ${err.message}`
      console.error(err)
      return false
    } finally {
      loading.value = false
    }
  }

  async function removeCluster(clusterName) {
    try {
      loading.value = true
      error.value = null
      
      await deleteCluster(clusterName)
      
      // Reload clusters to get the updated list
      await loadClusters()
      
      return true
    } catch (err) {
      error.value = `Failed to delete cluster: ${err.message}`
      console.error(err)
      return false
    } finally {
      loading.value = false
    }
  }

  // Clear cache manually if needed
  function clearCache() {
    localStorage.removeItem(CLUSTERS_STORAGE_KEY)
  }

  return {
    loading,
    error,
    clusters,
    showAddClusterModal,
    loadClusters,
    createCluster,
    removeCluster,
    clearCache,
    openAddClusterModal: () => { showAddClusterModal.value = true },
    closeAddClusterModal: () => { showAddClusterModal.value = false }
  }
} 