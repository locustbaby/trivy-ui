<template>
  <div>
    <div class="controls">
      <ClusterSelector
        v-model="selectedCluster"
        @update:modelValue="handleClusterChange"
      />
      <NamespaceSelector
        v-model="selectedNamespace"
        :options="namespaceOptions"
      />
      <n-button @click="loadData" type="primary" title="Load Reports">
        <template #icon>
          <n-icon><DownloadOutline /></n-icon>
        </template>
      </n-button>
      <n-button @click="refreshData" type="warning" class="refresh-btn" title="Refresh">
        <template #icon>
          <n-icon><RefreshOutline /></n-icon>
        </template>
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
    
    <n-data-table
      :columns="columns"
      :data="filteredReports"
      :pagination="pagination"
      :loading="loading"
      :bordered="false"
      stripe
      class="report-table"
    />
    
    <ReportDetailModal
      :show="showReportDetails"
      @update:show="showReportDetails = $event"
      :report="reportDetails"
    />
  </div>
</template>

<script>
import { ref, computed, onMounted, watch, h } from 'vue'
import { NButton, NInput, NIcon, NDataTable } from 'naive-ui'
import { SearchOutline, RefreshOutline, DownloadOutline } from '@vicons/ionicons5'
import { useTrivyData } from '../composables/useTrivyData'
import ClusterSelector from '../components/ClusterSelector.vue'
import NamespaceSelector from '../components/NamespaceSelector.vue'
import ReportDetailModal from '../components/ReportDetailModal.vue'
import { getVulnerabilityCount } from '../utils/formatters'

export default {
  components: {
    NButton,
    NInput,
    NIcon,
    NDataTable,
    SearchOutline,
    RefreshOutline,
    DownloadOutline,
    ClusterSelector,
    NamespaceSelector,
    ReportDetailModal
  },
  setup() {
    const { 
      loading, 
      error, 
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
      setSelectedCluster
    } = useTrivyData()

    // Add search functionality
    const searchQuery = ref('')
    
    // Add pagination control
    const pagination = {
      pageSize: 10
    }
    
    // Table columns definition
    const columns = [
      {
        title: 'Cluster',
        key: 'cluster',
        render(row) {
          return row.metadata?.labels?.['trivy-operator.cluster'] || 'N/A'
        }
      },
      {
        title: 'Name',
        key: 'metadata.name',
        render(row) {
          return row.metadata?.name || 'N/A'
        }
      },
      {
        title: 'Container Name',
        key: 'containerName',
        render(row) {
          return getContainerName(row)
        }
      },
      {
        title: 'Namespace',
        key: 'metadata.namespace',
        render(row) {
          return row.metadata?.namespace || 'N/A'
        }
      },
      {
        title: 'Resource',
        key: 'resource',
        render(row) {
          const kind = row.metadata?.labels?.['trivy-operator.resource.kind'] || 'Unknown'
          const name = row.metadata?.labels?.['trivy-operator.resource.name'] || 'Unknown'
          return `${kind}/${name}`
        }
      },
      {
        title: 'Critical',
        key: 'critical',
        render(row) {
          const count = getVulnerabilityCount(row, 'CRITICAL')
          return h('span', { 
            style: { 
              color: count > 0 ? '#ff4d4f' : '#999',
              fontWeight: count > 0 ? '500' : 'normal'
            } 
          }, count)
        }
      },
      {
        title: 'High',
        key: 'high',
        render(row) {
          const count = getVulnerabilityCount(row, 'HIGH')
          return h('span', { 
            style: { 
              color: count > 0 ? '#faad14' : '#999',
              fontWeight: count > 0 ? '500' : 'normal'
            } 
          }, count)
        }
      },
      {
        title: 'Medium',
        key: 'medium',
        render(row) {
          const count = getVulnerabilityCount(row, 'MEDIUM')
          return h('span', { 
            style: { 
              color: count > 0 ? '#1890ff' : '#999',
              fontWeight: count > 0 ? '500' : 'normal'
            } 
          }, count)
        }
      },
      {
        title: 'Low',
        key: 'low',
        render(row) {
          const count = getVulnerabilityCount(row, 'LOW')
          return h('span', { 
            style: { 
              color: count > 0 ? '#52c41a' : '#999',
              fontWeight: count > 0 ? '500' : 'normal'
            } 
          }, count)
        }
      },
      {
        title: 'Details',
        key: 'details',
        render(row) {
          return h(
            NButton,
            {
              size: 'small',
              onClick: () => viewReportDetails(row)
            },
            { default: () => 'View Details' }
          )
        }
      },
      {
        title: 'Created',
        key: 'metadata.creationTimestamp',
        render(row) {
          return row.metadata?.creationTimestamp || 'N/A'
        }
      }
    ]
    
    // Helper function to extract container name
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

    function handleClusterChange(cluster) {
      setSelectedCluster(cluster)
      loadNamespaces().then(() => {
        loadVulnerabilityReports()
      })
    }

    function loadData() {
      loadVulnerabilityReports()
    }
    
    function refreshData() {
      clearCache()
      Promise.all([
        loadClusters(),
        loadNamespaces()
      ]).then(() => {
        loadVulnerabilityReports()
      })
    }

    function viewReportDetails(report) {
      loadReportDetails(report)
    }

    onMounted(() => {
      // 先加载集群，然后加载命名空间，最后加载漏洞报告
      loadClusters().then(() => {
        if (selectedCluster.value) {
          return loadNamespaces()
        }
      }).then(() => {
        // 只有在有选中的命名空间和集群时才加载漏洞报告
        if (selectedNamespace.value && selectedCluster.value) {
          loadVulnerabilityReports()
        }
      }).catch(err => {
        console.error('Error loading initial data:', err)
      })
    })

    return {
      loading,
      error,
      selectedNamespace,
      selectedCluster,
      namespaceOptions,
      vulnerabilityReports,
      filteredReports,
      reportDetails,
      showReportDetails,
      searchQuery,
      pagination,
      columns,
      handleClusterChange,
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

.report-table {
  width: 100%;
  min-width: 1000px;
  table-layout: fixed;
  margin: 0 auto;
}

.report-table :deep(.n-data-table-td) {
  white-space: normal;
  word-break: break-word;
  max-width: 200px;
}

.report-table :deep(.n-data-table-th) {
  white-space: normal;
  word-break: break-word;
  max-width: 200px;
}

.report-table :deep(.n-data-table-cell) {
  padding: 12px;
}
</style>