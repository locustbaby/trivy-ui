import { ref, computed } from 'vue'
import { fetchClusters, addCluster, deleteCluster, updateCluster as updateClusterApi } from '../api/trivy'

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
      
      const response = await addCluster(clusterData)
      
      // 更新本地缓存
      const cachedClusters = JSON.parse(localStorage.getItem(CLUSTERS_STORAGE_KEY) || '[]')
      cachedClusters.push(response.data)
      localStorage.setItem(CLUSTERS_STORAGE_KEY, JSON.stringify(cachedClusters))
      
      // 重新加载集群列表
      await loadClusters()
      
      // 触发全局事件，通知其他组件集群已添加
      window.dispatchEvent(new CustomEvent('cluster-added', { 
        detail: { cluster: response.data } 
      }))
      
      return true
    } catch (err) {
      error.value = err.message
      console.error('Failed to create cluster:', err)
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
      
      // 更新本地缓存
      const cachedClusters = JSON.parse(localStorage.getItem(CLUSTERS_STORAGE_KEY) || '[]')
      const updatedClusters = cachedClusters.filter(c => c.name !== clusterName)
      localStorage.setItem(CLUSTERS_STORAGE_KEY, JSON.stringify(updatedClusters))
      
      // 重新加载集群列表
      await loadClusters()
      
      // 触发全局事件，通知其他组件集群已被删除
      window.dispatchEvent(new CustomEvent('cluster-deleted', { 
        detail: { clusterName } 
      }))
      
      return true
    } catch (err) {
      error.value = err.message
      console.error('Failed to delete cluster:', err)
      return false
    } finally {
      loading.value = false
    }
  }

  async function updateCluster(clusterData) {
    try {
      loading.value = true
      error.value = null
      
      await updateClusterApi(clusterData)
      
      // 更新本地缓存
      const cachedClusters = JSON.parse(localStorage.getItem(CLUSTERS_STORAGE_KEY) || '[]')
      const updatedClusters = cachedClusters.map(c => {
        if (c.name === clusterData.name) {
          return { ...c, ...clusterData }
        }
        return c
      })
      localStorage.setItem(CLUSTERS_STORAGE_KEY, JSON.stringify(updatedClusters))
      
      // 重新加载集群列表
      await loadClusters()
      
      // 触发全局事件，通知其他组件集群状态已更改
      window.dispatchEvent(new CustomEvent('cluster-status-changed', { 
        detail: { clusterName: clusterData.name, enabled: clusterData.enable } 
      }))
      
      return true
    } catch (err) {
      error.value = err.message
      console.error('Failed to update cluster:', err)
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
    updateCluster,
    clearCache,
    openAddClusterModal: () => { showAddClusterModal.value = true },
    closeAddClusterModal: () => { showAddClusterModal.value = false }
  }
} 