<template>
  <div class="cluster-selector">
    <n-select
      :value="modelValue"
      :options="clusterOptions"
      placeholder="Select Cluster"
      style="width: 200px; margin-right: 10px;"
      filterable
      remote
      :loading="loading"
      @search="handleSearch"
      @update:value="handleClusterChange"
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
    const clusterOptions = ref([])
    const loading = ref(false)

    const loadClusters = async (searchQuery = '') => {
      try {
        loading.value = true
        const clusters = await fetchClusters()
        console.log('Fetched clusters:', clusters)

        // Map clusters to options format
        clusterOptions.value = clusters
          .filter(cluster => cluster.enabled)
          .filter(cluster =>
            searchQuery ? cluster.name.toLowerCase().includes(searchQuery.toLowerCase()) : true
          )
          .map(cluster => ({
            label: cluster.name,
            value: cluster.name
          }))

        console.log('Mapped options:', clusterOptions.value)

        // If we have a modelValue but it's not in the options, add it
        if (props.modelValue && !clusterOptions.value.some(option => option.value === props.modelValue)) {
          clusterOptions.value.push({
            label: props.modelValue,
            value: props.modelValue
          })
        }

        if (props.modelValue) {
          const selectedClusterExists = clusterOptions.value.some(option => option.value === props.modelValue)
          if (!selectedClusterExists && clusterOptions.value.length > 0) {
            emit('update:modelValue', clusterOptions.value[0].value)
          }
        }
      } catch (error) {
        console.error('Failed to load clusters:', error)
        // If we have a modelValue but loading failed, ensure it's still in the options
        if (props.modelValue && !clusterOptions.value.some(option => option.value === props.modelValue)) {
          clusterOptions.value.push({
            label: props.modelValue,
            value: props.modelValue
          })
        }
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

    const handleClusterChange = (value) => {
      // Emit the update event with the new value
      emit('update:modelValue', value)
    }

    return {
      clusterOptions,
      loading,
      handleSearch,
      handleClusterChange
    }
  }
}
</script>

<style scoped>
.cluster-selector {
  display: inline-block;
}
</style>