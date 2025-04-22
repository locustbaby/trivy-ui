import { ref, computed } from 'vue'
import { fetchClusters, addCluster, deleteCluster, updateCluster as updateClusterApi } from '../api/trivy'

// Storage key constants
const CLUSTERS_STORAGE_KEY = 'trivy-clusters'
const CACHE_EXPIRATION_KEY = 'trivy-cache-expiration'
const CLUSTER_ENABLE_STATE_KEY = 'trivy-cluster-enable-state'

// Cache expiration time (in milliseconds) - 30 minutes (matching backend)
const CACHE_EXPIRATION_TIME = 30 * 60 * 1000

export function useClusterData() {
  const loading = ref(false)
  const error = ref(null)
  const clusters = ref([])
  const showAddClusterModal = ref(false)
  const selectedCluster = ref(null)

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

  // Get enable state for a cluster
  function getClusterEnableState(clusterName) {
    const enableState = JSON.parse(localStorage.getItem(CLUSTER_ENABLE_STATE_KEY) || '{}')
    return enableState[clusterName] !== false // Default to true if not set
  }

  // Set enable state for a cluster
  function setClusterEnableState(clusterName, enable) {
    try {
      const enableState = JSON.parse(localStorage.getItem(CLUSTER_ENABLE_STATE_KEY) || '{}')
      enableState[clusterName] = enable
      localStorage.setItem(CLUSTER_ENABLE_STATE_KEY, JSON.stringify(enableState))
    } catch (err) {
      console.warn('Failed to save cluster enable state:', err.message)
      // This is a non-critical error, so we can continue
    }
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
        const fetchedClusters = await fetchClusters()

        // Add enable state to each cluster
        clusters.value = fetchedClusters.map(cluster => ({
          ...cluster,
          enable: getClusterEnableState(cluster.name)
        }))

        // Cache the clusters with error handling
        try {
          localStorage.setItem(CLUSTERS_STORAGE_KEY, JSON.stringify(clusters.value))
          updateCacheExpiration()
        } catch (err) {
          console.warn('Failed to cache clusters:', err.message)
          // If storage quota is exceeded, we can ignore it for clusters
          // since they are small and essential
        }
      }
    } catch (err) {
      error.value = `Failed to fetch clusters: ${err.message}`
      console.error('Error loading clusters:', err)
    } finally {
      loading.value = false
    }
  }

  // Get enabled clusters
  const enabledClusters = computed(() => {
    return clusters.value.filter(cluster => cluster.enable)
  })

  async function createCluster(clusterData) {
    try {
      loading.value = true
      error.value = null

      const response = await addCluster(clusterData)

      if (response.code === 0) {
        // Set default enable state to true
        setClusterEnableState(clusterData.name, true)

        // Add the new cluster to the list
        const newCluster = {
          ...clusterData,
          enable: true,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        }

        clusters.value.push(newCluster)

        // Update cache with error handling
        try {
          localStorage.setItem(CLUSTERS_STORAGE_KEY, JSON.stringify(clusters.value))
          updateCacheExpiration()
        } catch (err) {
          console.warn('Failed to update clusters cache:', err.message)
        }

        // Dispatch event
        window.dispatchEvent(new CustomEvent('cluster-added', {
          detail: { cluster: newCluster }
        }))

        return newCluster
      } else {
        throw new Error(response.message || 'Failed to create cluster')
      }
    } catch (err) {
      error.value = `Failed to create cluster: ${err.message}`
      console.error('Error creating cluster:', err)
      throw err
    } finally {
      loading.value = false
    }
  }

  async function removeCluster(clusterName) {
    try {
      loading.value = true
      error.value = null

      const response = await deleteCluster(clusterName)

      if (response.code === 0) {
        // Remove enable state with error handling
        try {
          const enableState = JSON.parse(localStorage.getItem(CLUSTER_ENABLE_STATE_KEY) || '{}')
          delete enableState[clusterName]
          localStorage.setItem(CLUSTER_ENABLE_STATE_KEY, JSON.stringify(enableState))
        } catch (err) {
          console.warn('Failed to remove cluster enable state:', err.message)
          // This is a non-critical error, so we can continue
        }

        // Remove from list
        clusters.value = clusters.value.filter(c => c.name !== clusterName)

        // Update cache with error handling
        try {
          localStorage.setItem(CLUSTERS_STORAGE_KEY, JSON.stringify(clusters.value))
          updateCacheExpiration()
        } catch (err) {
          console.warn('Failed to update clusters cache:', err.message)
        }

        // Dispatch event
        window.dispatchEvent(new CustomEvent('cluster-deleted', {
          detail: { clusterName }
        }))

        return true
      } else {
        throw new Error(response.message || 'Failed to delete cluster')
      }
    } catch (err) {
      error.value = `Failed to delete cluster: ${err.message}`
      console.error('Error deleting cluster:', err)
      throw err
    } finally {
      loading.value = false
    }
  }

  async function updateCluster(clusterData) {
    try {
      loading.value = true
      error.value = null

      // If only the enable state is changing, update it locally
      if (clusterData.hasOwnProperty('enable') && Object.keys(clusterData).length === 1) {
        console.log('Updating enable state locally:', clusterData)
        setClusterEnableState(clusterData.name, clusterData.enable)

        // Update the cluster in the list
        const index = clusters.value.findIndex(c => c.name === clusterData.name)
        if (index !== -1) {
          clusters.value[index] = {
            ...clusters.value[index],
            enable: clusterData.enable
          }

          // Update cache with error handling
          try {
            localStorage.setItem(CLUSTERS_STORAGE_KEY, JSON.stringify(clusters.value))
            updateCacheExpiration()
          } catch (err) {
            console.warn('Failed to update clusters cache:', err.message)
          }

          // Dispatch event
          window.dispatchEvent(new CustomEvent('cluster-status-changed', {
            detail: {
              clusterName: clusterData.name,
              enabled: clusterData.enable
            }
          }))

          return clusters.value[index]
        }
        return null
      }

      // For other updates, call the API
      const response = await updateClusterApi(clusterData)

      if (response.code === 0) {
        // Update the cluster in the list
        const index = clusters.value.findIndex(c => c.name === clusterData.name)
        if (index !== -1) {
          clusters.value[index] = {
            ...clusters.value[index],
            ...clusterData,
            updated_at: new Date().toISOString()
          }

          // Update cache with error handling
          try {
            localStorage.setItem(CLUSTERS_STORAGE_KEY, JSON.stringify(clusters.value))
            updateCacheExpiration()
          } catch (err) {
            console.warn('Failed to update clusters cache:', err.message)
          }

          return clusters.value[index]
        }
        return null
      } else {
        throw new Error(response.message || 'Failed to update cluster')
      }
    } catch (err) {
      error.value = `Failed to update cluster: ${err.message}`
      console.error('Error updating cluster:', err)
      throw err
    } finally {
      loading.value = false
    }
  }

  // Load clusters on initialization
  loadClusters()

  function clearCache() {
    // Clear clusters cache
    localStorage.removeItem(CLUSTERS_STORAGE_KEY)

    // Clear cache expiration
    localStorage.removeItem(CACHE_EXPIRATION_KEY)

    // Note: We don't clear CLUSTER_ENABLE_STATE_KEY because that's user preference
    // and should persist even when refreshing data
  }

  function openAddClusterModal() {
    showAddClusterModal.value = true
  }

  function closeAddClusterModal() {
    showAddClusterModal.value = false
  }

  // Listen for cluster status change events
  if (typeof window !== 'undefined') {
    window.addEventListener('cluster-status-changed', (event) => {
      const { clusterName, enabled } = event.detail

      // If the cluster was disabled, remove it from the list and clear its cache
      if (!enabled) {
        // Remove the cluster from the list
        clusters.value = clusters.value.filter(c => c.name !== clusterName)

        // Clear the cluster's cache
        const cacheKey = `trivy-reports-vulnerabilityreports-${clusterName}`
        localStorage.removeItem(cacheKey)

        // If the disabled cluster was selected, clear the selection
        if (selectedCluster.value === clusterName) {
          selectedCluster.value = null
        }
      }
    })
  }

  return {
    loading,
    error,
    clusters,
    enabledClusters,
    showAddClusterModal,
    loadClusters,
    createCluster,
    removeCluster,
    updateCluster,
    clearCache,
    openAddClusterModal,
    closeAddClusterModal,
    selectedCluster
  }
}