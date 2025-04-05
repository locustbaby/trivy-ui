<template>
  <div class="cluster-selector">
    <n-select
      :value="modelValue"
      :options="options"
      placeholder="Select Cluster"
      style="width: 200px; margin-right: 10px;"
      filterable
      remote
      :loading="loading"
      @search="handleSearch"
      @update:value="$emit('update:modelValue', $event)"
    />
  </div>
</template>

<script>
import { ref, watch, onMounted, onUnmounted } from 'vue'
import { NSelect } from 'naive-ui'
import { fetchClusters } from '../api/trivy'

export default {
  components: {
    NSelect
  },
  props: {
    modelValue: {
      type: String,
      default: null
    }
  },
  emits: ['update:modelValue'],
  setup(props, { emit }) {
    const options = ref([])
    const loading = ref(false)

    const loadClusters = async (searchQuery = '') => {
      try {
        loading.value = true
        const clusters = await fetchClusters()
        options.value = clusters
          .filter(cluster => 
            cluster.enable &&
            cluster.name.toLowerCase().includes(searchQuery.toLowerCase())
          )
          .map(cluster => ({
            label: cluster.name,
            value: cluster.name
          }))
          
        if (props.modelValue) {
          const selectedClusterExists = options.value.some(option => option.value === props.modelValue)
          if (!selectedClusterExists && options.value.length > 0) {
            emit('update:modelValue', options.value[0].value)
          }
        }
      } catch (error) {
        console.error('Failed to load clusters:', error)
      } finally {
        loading.value = false
      }
    }

    const handleSearch = (query) => {
      loadClusters(query)
    }
    
    const handleClusterStatusChanged = (event) => {
      const { clusterName, enabled } = event.detail
      
      if (props.modelValue === clusterName && !enabled) {
        loadClusters()
      }
    }
    
    const handleClusterDeleted = (event) => {
      const { clusterName } = event.detail
      
      if (props.modelValue === clusterName) {
        loadClusters()
      }
    }

    onMounted(() => {
      window.addEventListener('cluster-status-changed', handleClusterStatusChanged)
      window.addEventListener('cluster-deleted', handleClusterDeleted)
      loadClusters()
    })
    
    onUnmounted(() => {
      window.removeEventListener('cluster-status-changed', handleClusterStatusChanged)
      window.removeEventListener('cluster-deleted', handleClusterDeleted)
    })

    return {
      options,
      loading,
      handleSearch
    }
  }
}
</script> 