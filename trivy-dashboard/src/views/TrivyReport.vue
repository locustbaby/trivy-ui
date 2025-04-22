<template>
  <div class="report-container">
    <div class="table-wrapper">
      <div class="controls">
        <div class="selector-group">
          <div class="selector-title">Cluster</div>
          <ClusterSelector
            v-model="selectedCluster"
            @update:modelValue="handleClusterChange"
          />
        </div>
        <!-- Only show namespace selector for namespace-level reports -->
        <div class="selector-group" v-if="!isClusterLevelReport(currentReportType)">
          <div class="selector-title">Namespace</div>
          <NamespaceSelector
            v-model="selectedNamespace"
            :options="namespaceOptions"
          />
        </div>
        <!-- Load button removed as data is now loaded automatically when namespace changes -->
        <n-button
          @click="refreshData"
          type="warning"
          class="refresh-btn"
          title="Refresh"
          :loading="isRefreshing"
          :disabled="isRefreshing"
        >
          <template #icon>
            <n-icon><RefreshOutline /></n-icon>
          </template>
          {{ isRefreshing ? 'Refreshing...' : 'Refresh' }}
        </n-button>
      </div>

      <!-- Filter controls -->
      <div class="filter-container">
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

      </div>

      <div v-if="error" class="error">{{ error }}</div>

      <div class="table-content">
        <div v-if="loading" class="loading">Loading data...</div>

        <div class="table-area">
          <n-data-table
            v-if="filteredReports.length > 0"
            :columns="columns"
            :data="filteredReports"
            :loading="loading"
            :bordered="false"
            :pagination="pagination"
            stripe
            class="report-table"
          />
          <div v-if="!loading && filteredReports.length === 0" class="no-data">
            No data available
          </div>
        </div>
      </div>
    </div>

    <ReportDetailModal
      :show="showReportDetails"
      @update:show="showReportDetails = $event"
      :report="reportDetails"
      :reportType="currentReportType"
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
import { useClusterData } from '../composables/useClusterData'
import { fetchReportDetails } from '../api/trivy'
import { getSeverityCount, isVulnerabilityReport, isConfigAuditReport, isExposedSecretReport, getResourceInfo, getReportLevel, isClusterLevelReport } from '../utils/reportTypeUtils'

export default {
  name: 'TrivyReport',
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
  props: {
    reportType: {
      type: String,
      default: 'vulnerabilityreports',
      required: false
    }
  },
  setup(props) {
    const {
      loading,
      error,
      reports,
      clusters,
      namespaces,
      selectedCluster,
      selectedNamespace,
      searchQuery,
      loadReports,
      loadNamespaces,
      handleClusterChange,
      handleNamespaceChange,
      handleSearch,
      showReportDetails,
      reportDetails,
      setReportType,
      currentReportType,
      clearCache
    } = useTrivyData(props.reportType)

    // Get enabled clusters
    const { enabledClusters, loadClusters } = useClusterData()

    // Watch for changes in enabled clusters
    watch(enabledClusters, () => {
      // If the selected cluster is disabled, reset it
      if (selectedCluster.value && !enabledClusters.value.some(c => c.name === selectedCluster.value)) {
        selectedCluster.value = null
      }
    })

    // Filter clusters to only show enabled ones
    const availableClusters = computed(() => {
      return enabledClusters.value.map(cluster => ({
        label: cluster.name,
        value: cluster.name
      }))
    })

    // Create namespace options for the selector
    const namespaceOptions = computed(() => {
      return namespaces.value.map(ns => ({
        label: ns,
        value: ns
      }))
    })

    // Watch for report type changes
    watch(() => props.reportType, (newType) => {
      setReportType(newType)
    }, { immediate: true })

    // Watch for cluster changes and automatically load namespaces and data
    watch(selectedCluster, (newCluster, oldCluster) => {
      // Only load data if we have a valid cluster and it's different from the previous one
      if (newCluster && newCluster !== oldCluster) {
        console.log(`Cluster changed from ${oldCluster} to ${newCluster}, loading namespaces...`)
        // Use the existing handleClusterChange function which handles loading namespaces and reports
        handleClusterChange(newCluster)
      }
    })

    // Watch for namespace changes and automatically load data
    watch(selectedNamespace, (newNamespace, oldNamespace) => {
      // Only load data if we have a valid namespace and it's different from the previous one
      if (newNamespace && newNamespace !== oldNamespace && selectedCluster.value) {
        console.log(`Namespace changed from ${oldNamespace} to ${newNamespace}, loading data...`)
        // Use the existing handleNamespaceChange function which handles loading reports
        handleNamespaceChange(newNamespace)
      }
    })

    // Report level filter removed

    // Add pagination control
    const pagination = {
      pageSize: 10,
      showSizePicker: true,
      pageSizes: [10, 20, 50, 100],
      showPageSize: true
    }

    // Table columns definition
    const columns = computed(() => {
      // Common columns for all report types
      const commonColumns = [
      {
        title: 'Cluster',
        key: 'cluster',
        render(row) {
          // Try to get cluster name from different possible sources
          const clusterName = row.metadata?.labels?.['trivy-operator.cluster.name'] ||
                            row.metadata?.labels?.['trivy-operator.cluster'] ||
                            row.cluster ||
                            selectedCluster.value ||  // Add selected cluster as fallback
                            'N/A';
          return h('div', {
            style: {
              color: '#333',
              fontWeight: 'normal'
            }
          }, clusterName)
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
      // Only show namespace column for namespace-level reports
      ...(!isClusterLevelReport(currentReportType.value) ? [{
        title: 'Namespace',
        key: 'metadata.namespace',
        render(row) {
          return row.metadata?.namespace || 'N/A'
        }
      }] : []),

      {
        title: 'Resource',
        key: 'resource',
        render(row) {
          // Try to get resource kind and name from different possible locations
          let kind = row.metadata?.labels?.['trivy-operator.resource.kind']
          let name = row.metadata?.labels?.['trivy-operator.resource.name']

          // If not found in labels, try to get from data.metadata.labels
          if (!kind || !name) {
            kind = row.data?.metadata?.labels?.['trivy-operator.resource.kind'] ||
                  row.metadata?.labels?.['resource.kind'] ||
                  row.data?.metadata?.labels?.['resource.kind']

            name = row.data?.metadata?.labels?.['trivy-operator.resource.name'] ||
                   row.metadata?.labels?.['resource.name'] ||
                   row.data?.metadata?.labels?.['resource.name']
          }

          // If still not found, try to extract from the report name
          if (!kind || !name) {
            const reportName = row.metadata?.name || ''
            const parts = reportName.split('-')
            if (parts.length >= 3) {
              // The format is often something like: 'vulnerabilityreport-deployment-nginx'
              kind = parts[1] || ''
              name = parts.slice(2).join('-') || ''

              // Capitalize the first letter of kind
              if (kind) {
                kind = kind.charAt(0).toUpperCase() + kind.slice(1)
              }
            }
          }

          return kind && name ? `${kind}/${name}` : 'N/A'
        }
      },
      ];

      // Severity columns - only show for report types that have severity information
      const severityColumns = [];

      // For vulnerability reports and config audit reports, show all severity levels
      if (isVulnerabilityReport(currentReportType.value) ||
          isConfigAuditReport(currentReportType.value) ||
          isExposedSecretReport(currentReportType.value)) {

        severityColumns.push(
          {
            title: 'Critical',
            key: 'critical',
            render(row) {
              const count = getSeverityCount(row, 'CRITICAL', currentReportType.value);
              return h('span', {
                style: {
                  color: count > 0 ? '#ff4d4f' : '#999',
                  fontWeight: count > 0 ? '500' : 'normal'
                }
              }, count.toString())
            }
          },
          {
            title: 'High',
            key: 'high',
            render(row) {
              const count = getSeverityCount(row, 'HIGH', currentReportType.value);
              return h('span', {
                style: {
                  color: count > 0 ? '#faad14' : '#999',
                  fontWeight: count > 0 ? '500' : 'normal'
                }
              }, count.toString())
            }
          },
          {
            title: 'Medium',
            key: 'medium',
            render(row) {
              const count = getSeverityCount(row, 'MEDIUM', currentReportType.value);
              return h('span', {
                style: {
                  color: count > 0 ? '#1890ff' : '#999',
                  fontWeight: count > 0 ? '500' : 'normal'
                }
              }, count.toString())
            }
          },
          {
            title: 'Low',
            key: 'low',
            render(row) {
              const count = getSeverityCount(row, 'LOW', currentReportType.value);
              return h('span', {
                style: {
                  color: count > 0 ? '#52c41a' : '#999',
                  fontWeight: count > 0 ? '500' : 'normal'
                }
              }, count.toString())
            }
          }
        );
      }

      // Common action and metadata columns
      const actionColumns = [{
        title: 'Details',
        key: 'details',
        render(row) {
          return h(
            NButton,
            {
              size: 'small',
              onClick: () => handleViewDetails(row),
              style: {
                minWidth: '90px'
              }
            },
            { default: () => 'View Details' }
          )
        }
      },
      {
        title: 'Created',
        key: 'created',
        render(row) {
          const timestamp = row.metadata?.creationTimestamp
          if (!timestamp) return 'N/A'
          try {
            const date = new Date(timestamp)
            return date.toLocaleString()
          } catch (e) {
            return timestamp
          }
        }
      }];

      // Combine all columns and return
      return [...commonColumns, ...severityColumns, ...actionColumns];
    })

    // Helper function to extract container name
    function getContainerName(report) {
      return report.metadata?.labels?.['trivy-operator.container.name'] ||
             (report.metadata?.name || '').split('-').pop() ||
             ''
    }

    // Filter reports by name, container name, and level
    const filteredReports = computed(() => {
      if (!reports.value || !Array.isArray(reports.value)) {
        return []
      }

      // Start with all reports
      let filtered = reports.value

      // Apply search query filter
      if (searchQuery.value) {
        const query = searchQuery.value.toLowerCase().trim()
        filtered = filtered.filter(report => {
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
      }

      return filtered
    })

    function loadData() {
      // For cluster-level reports, we only need the cluster to be selected
      // For namespace-level reports, we need both cluster and namespace
      const isClusterLevel = isClusterLevelReport(currentReportType.value)

      if (selectedCluster.value && (isClusterLevel || selectedNamespace.value)) {
        loadReports()
      }
    }

    // Add throttling for refresh button
    const lastRefreshTime = ref(0)
    const refreshThrottleTime = 10000 // 10 seconds
    const isRefreshing = ref(false)

    function refreshData() {
      // Check if we're already refreshing
      if (isRefreshing.value) {
        console.log('Refresh already in progress, ignoring request')
        return
      }

      // Check if we've refreshed recently
      const now = Date.now()
      if (now - lastRefreshTime.value < refreshThrottleTime) {
        console.log(`Refresh throttled. Please wait ${Math.ceil((refreshThrottleTime - (now - lastRefreshTime.value)) / 1000)} seconds before refreshing again.`)
        return
      }

      // Set refreshing state
      isRefreshing.value = true
      lastRefreshTime.value = now

      // Clear cache first
      clearCache()

      // Check if this is a cluster-level report
      const isClusterLevel = isClusterLevelReport(currentReportType.value)

      // For cluster-level reports, we can load reports directly
      if (isClusterLevel) {
        loadReports(true).finally(() => {
          // Reset refreshing state
          isRefreshing.value = false
        })
      } else {
        // For namespace-level reports, load namespaces first
        loadNamespaces().then(() => {
          if (selectedNamespace.value) {
            loadReports(true).finally(() => {
              // Reset refreshing state
              isRefreshing.value = false
            })
          } else {
            isRefreshing.value = false
          }
        }).catch(() => {
          isRefreshing.value = false
        })
      }
    }

    async function handleViewDetails(report) {
      try {
        loading.value = true
        error.value = null

        console.log('Original report:', report)

        // Fetch report details
        const response = await fetchReportDetails(
          currentReportType.value,
          selectedCluster.value,
          selectedNamespace.value,
          report.metadata.name
        )

        console.log('API Response:', response)

        if (response?.data) {
          // The API returns the report data in the data field
          const reportData = response.data

          console.log('Report data from API:', reportData)

          // Create a properly structured report object based on report type
          const transformedReport = {
            metadata: {
              name: reportData.name,
              namespace: reportData.namespace,
              creationTimestamp: reportData.data?.metadata?.creationTimestamp,
              labels: reportData.data?.metadata?.labels || {}
            },
            // Preserve the original data structure for different report types
            data: reportData.data || {},
            report: reportData.data?.report || {}
          }

          console.log('Transformed report:', transformedReport)

          reportDetails.value = transformedReport
          showReportDetails.value = true
        } else {
          error.value = 'Failed to load report details'
        }
      } catch (err) {
        console.error('Error loading report details:', err)
        error.value = err.message || 'Failed to load report details'
      } finally {
        loading.value = false
      }
    }

    onMounted(() => {
      // Load clusters first
      loadClusters().then(() => {
        // If no cluster is selected, try to select the first enabled cluster
        if (!selectedCluster.value && enabledClusters.value.length > 0) {
          selectedCluster.value = enabledClusters.value[0].name
        }

        // Check if this is a cluster-level report
        const isClusterLevel = isClusterLevelReport(currentReportType.value)

        // Only proceed with loading if we have a selected cluster
        if (selectedCluster.value) {
          // For cluster-level reports, we can load reports directly
          if (isClusterLevel) {
            loadReports()
          } else {
            // For namespace-level reports, load namespaces first
            loadNamespaces().then(() => {
              // If we have namespaces but no namespace is selected, select the first one
              if (namespaces.value.length > 0 && !selectedNamespace.value) {
                selectedNamespace.value = namespaces.value[0]
              }

              // Now load reports if we have a namespace selected
              if (selectedNamespace.value) {
                loadReports()
              }
            }).catch(err => {
              console.error('Error loading namespaces:', err)
            })
          }
        }
      }).catch(err => {
        console.error('Error loading clusters:', err)
      })

      // Listen for cluster status change events
      window.addEventListener('cluster-status-changed', (event) => {
        const { clusterName, enabled } = event.detail

        // If the cluster was enabled and it's the currently selected cluster
        if (enabled && selectedCluster.value === clusterName) {
          // Check if this is a cluster-level report
          const isClusterLevel = isClusterLevelReport(currentReportType.value)

          // For cluster-level reports, we can load reports directly
          if (isClusterLevel) {
            loadReports()
          } else {
            // For namespace-level reports, load namespaces first
            loadNamespaces().then(() => {
              // If we have namespaces but no namespace is selected, select the first one
              if (namespaces.value.length > 0 && !selectedNamespace.value) {
                selectedNamespace.value = namespaces.value[0]
              }

              // Now load reports if we have a namespace selected
              if (selectedNamespace.value) {
                loadReports()
              }
            }).catch(err => {
              console.error('Error reloading data after cluster enabled:', err)
            })
          }
        }
      })
    })

    return {
      loading,
      error,
      reports,
      clusters: availableClusters,
      namespaces,
      selectedCluster,
      selectedNamespace,
      namespaceOptions,
      filteredReports,
      reportDetails,
      showReportDetails,
      searchQuery,
      pagination,
      columns,
      isRefreshing,
      handleClusterChange,
      loadData,
      refreshData,
      handleViewDetails,
      isClusterLevelReport,
      currentReportType
    }
  }
}
</script>

<style scoped>
.report-container {
  padding: 20px;
  width: 100%;
  box-sizing: border-box;
  display: flex;
  flex-direction: column;
}

.table-wrapper {
  flex: 1;
  width: 100%;
  min-width: 800px;
  max-width: 1200px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.controls {
  display: flex;
  gap: 10px;
  align-items: flex-end;
  width: 100%;
  background: transparent;
  position: relative;
}

.selector-group {
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 200px;
}

.selector-title {
  font-size: 12px;
  color: #666;
  margin-bottom: 2px;
}

.filter-container {
  width: 100%;
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 10px;
}

.search-container {
  flex: 1;
}

.search-input {
  max-width: 400px;
}

.table-content {
  width: 100%;
  min-height: 400px;
  background: #fff;
  border-radius: 8px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
  position: relative;
}

.table-area {
  width: 100%;
  min-height: 400px;
  position: relative;
}

.loading, .no-data {
  width: 100%;
  min-height: 400px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #fff;
  border-radius: 8px;
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  z-index: 2;
}

.loading {
  font-style: italic;
}

.no-data {
  color: #999;
  font-size: 14px;
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
  position: relative;
  z-index: 2;
}

.report-table {
  width: 100%;
}

.report-table :deep(.n-data-table-wrapper) {
  width: 100%;
  position: relative;
  z-index: 1;
}

.report-table :deep(.n-data-table) {
  width: 100%;
  table-layout: fixed;
  position: relative;
  z-index: 1;
}

.report-table :deep(.n-data-table-td) {
  white-space: normal;
  word-break: break-word;
  padding: 12px 16px;
}

.report-table :deep(.n-data-table-th) {
  white-space: normal;
  word-break: break-word;
  padding: 12px 16px;
  background-color: #fafafa;
}

.report-table :deep(.n-data-table-tr) {
  width: 100%;
}

.report-table :deep(.n-data-table-th-column) {
  width: 100%;
}

.report-table :deep(.n-data-table-td.cluster),
.report-table :deep(.n-data-table-th.cluster) {
  width: 120px;
}

.report-table :deep(.n-data-table-td.name),
.report-table :deep(.n-data-table-th.name) {
  width: 200px;
}

.report-table :deep(.n-data-table-td.container-name),
.report-table :deep(.n-data-table-th.container-name) {
  width: 150px;
}

.report-table :deep(.n-data-table-td.namespace),
.report-table :deep(.n-data-table-th.namespace) {
  width: 120px;
}

.report-table :deep(.n-data-table-td.resource),
.report-table :deep(.n-data-table-th.resource) {
  width: 150px;
}

.report-table :deep(.n-data-table-td.severity),
.report-table :deep(.n-data-table-th.severity) {
  width: 80px;
  text-align: center;
}

/* Fix for Low, Medium, High, Critical columns to prevent wrapping */
.report-table :deep(.n-data-table-td.low),
.report-table :deep(.n-data-table-th.low),
.report-table :deep(.n-data-table-td.medium),
.report-table :deep(.n-data-table-th.medium),
.report-table :deep(.n-data-table-td.high),
.report-table :deep(.n-data-table-th.high),
.report-table :deep(.n-data-table-td.critical),
.report-table :deep(.n-data-table-th.critical) {
  width: 80px;
  text-align: center;
  white-space: nowrap;
}

.report-table :deep(.n-data-table-td.details),
.report-table :deep(.n-data-table-th.details) {
  width: 100px;
  text-align: center;
}

.report-table :deep(.n-data-table-td.created),
.report-table :deep(.n-data-table-th.created) {
  width: 180px;
}

:deep(.n-tabs-content) {
  width: 100%;
}
</style>