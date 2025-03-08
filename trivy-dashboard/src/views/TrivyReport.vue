<template>
  <div>
    <h1>Trivy Vulnerability Dashboard</h1>
    <div class="controls">
      <NamespaceSelector
        v-model="selectedNamespace"
        :options="namespaceOptions"
      />
      <n-button @click="loadData" type="primary">Load Reports</n-button>
      <n-button @click="refreshData" type="warning" class="refresh-btn">
        <template #icon>
          <n-icon><RefreshOutline /></n-icon>
        </template>
        Refresh
      </n-button>
    </div>

    <!-- Search box -->
    <div class="search-container">
      <n-input
        v-model:value="searchQuery"
        placeholder="Search reports..."
        clearable
        class="search-input"
      >
        <template #prefix>
          <n-icon><SearchOutline /></n-icon>
        </template>
      </n-input>
    </div>
    
    <div v-if="loading" class="loading">Loading data...</div>
    <div v-if="error" class="error">{{ error }}</div>
    
    <VulnerabilityTable 
      :reports="filteredReports"
      :page-size="pageSize" 
      @update:page-size="pageSize = $event"
      @view-details="viewReportDetails" 
    />
    
    <ReportDetailModal
      :show="showReportDetails"
      @update:show="showReportDetails = $event"
      :report="reportDetails"
    />
  </div>
</template>

<script>
import { ref, computed, onMounted, watch } from 'vue'
import { NButton, NInput, NIcon } from 'naive-ui'
import { SearchOutline, RefreshOutline } from '@vicons/ionicons5'
import { useTrivyData } from '../composables/useTrivyData'
import NamespaceSelector from '../components/NamespaceSelector.vue'
import VulnerabilityTable from '../components/VulnerabilityTable.vue'
import ReportDetailModal from '../components/ReportDetailModal.vue'

export default {
  components: {
    NButton,
    NInput,
    NIcon,
    SearchOutline,
    RefreshOutline,
    NamespaceSelector,
    VulnerabilityTable,
    ReportDetailModal
  },
  setup() {
    const { 
      loading, 
      error, 
      selectedNamespace,
      namespaceOptions,
      vulnerabilityReports,
      reportDetails,
      showReportDetails,
      loadNamespaces,
      loadVulnerabilityReports,
      loadReportDetails,
      clearCache
    } = useTrivyData()

    // Add search functionality
    const searchQuery = ref('')
    
    // Add pagination control
    const pageSize = ref(10)
    
    // Try to load page size from localStorage
    try {
      const storedPageSize = localStorage.getItem('trivy-page-size')
      if (storedPageSize) {
        pageSize.value = parseInt(storedPageSize, 10)
      }
    } catch (e) {
      console.warn('Failed to load page size from localStorage:', e)
    }
    
    // Save page size to localStorage when it changes
    watch(pageSize, (newValue) => {
      localStorage.setItem('trivy-page-size', newValue.toString())
    })
    
    // Helper function to extract container name - ensure consistency with VulnerabilityTable component
    function getContainerName(report) {
      return report.metadata?.labels?.['trivy-operator.container.name'] || 
             (report.metadata?.name || '').split('-').pop() || 
             ''
    }
    
    // Filter reports by name and container name
    const filteredReports = computed(() => {
      if (!searchQuery.value) return vulnerabilityReports.value
      
      const query = searchQuery.value.toLowerCase().trim()
      return vulnerabilityReports.value.filter(report => {
        // Search in report name
        if ((report.metadata?.name || '').toLowerCase().includes(query)) return true
        
        // Search in container name
        const containerName = getContainerName(report)
        if (containerName.toLowerCase().includes(query)) return true
        
        // Search in resource name/kind
        const resourceKind = report.metadata?.labels?.['trivy-operator.resource.kind'] || ''
        const resourceName = report.metadata?.labels?.['trivy-operator.resource.name'] || ''
        if (resourceKind.toLowerCase().includes(query) || resourceName.toLowerCase().includes(query)) return true
        
        return false
      })
    })

    function loadData() {
      loadVulnerabilityReports()
    }
    
    function refreshData() {
      clearCache()
      loadNamespaces().then(() => {
        loadVulnerabilityReports()
      })
    }

    function viewReportDetails(report) {
      loadReportDetails(report)
    }

    onMounted(() => {
      loadNamespaces().then(() => {
        // Load reports automatically if we have a selected namespace from cache
        if (selectedNamespace.value) {
          loadVulnerabilityReports()
        }
      })
    })

    return {
      loading,
      error,
      selectedNamespace,
      namespaceOptions,
      vulnerabilityReports,
      filteredReports,
      reportDetails,
      showReportDetails,
      searchQuery,
      pageSize,
      loadData,
      refreshData,
      viewReportDetails
    }
  }
}
</script>

<style scoped>
.controls {
  display: flex;
  margin-bottom: 20px;
  gap: 10px;
}
.search-container {
  margin-bottom: 20px;
}
.search-input {
  max-width: 400px;
}
.loading {
  padding: 20px;
  text-align: center;
  font-style: italic;
}
.error {
  padding: 10px;
  color: red;
  border: 1px solid red;
  border-radius: 4px;
  margin-bottom: 10px;
}
.refresh-btn {
  margin-left: auto;
}
</style>