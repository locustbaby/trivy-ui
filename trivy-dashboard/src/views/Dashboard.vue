<template>
  <div class="dashboard">
    <div class="header">
      <h1>Trivy Dashboard</h1>
      <div class="selector-group">
        <div class="selector-title">Report Type</div>
        <n-select
          v-model:value="activeTab"
          :options="reportTypeOptions"
          class="report-type-selector"
          :loading="loading"
        />
      </div>
    </div>
    <div class="content">
      <n-tabs v-model:value="activeView" type="line" animated>
        <n-tab-pane name="reports" tab="Reports">
          <TrivyReport :report-type="activeTab" />
        </n-tab-pane>
        <n-tab-pane name="clusters" tab="Cluster Management">
          <ClusterManager />
        </n-tab-pane>
      </n-tabs>
    </div>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'
import { NSelect, NTabs, NTabPane } from 'naive-ui'
import TrivyReport from './TrivyReport.vue'
import ClusterManager from './ClusterManager.vue'
import { fetchReportTypes } from '../api/trivy'

export default {
  name: 'Dashboard',
  components: {
    NSelect,
    NTabs,
    NTabPane,
    TrivyReport,
    ClusterManager
  },
  setup() {
    const activeTab = ref('vulnerabilityreports')
    const activeView = ref('reports')
    const reportTypeOptions = ref([])
    const loading = ref(false)
    
    const loadReportTypes = async () => {
      try {
        loading.value = true
        const types = await fetchReportTypes()
        reportTypeOptions.value = types.map(type => ({
          label: type.charAt(0).toUpperCase() + type.slice(1).replace(/([A-Z])/g, ' $1'),
          value: type
        }))
        
        // Select vulnerabilityreports by default if available
        if (types.includes('vulnerabilityreports')) {
          activeTab.value = 'vulnerabilityreports'
        } else if (types.length > 0) {
          activeTab.value = types[0]
        }
      } catch (error) {
        console.error('Failed to load report types:', error)
      } finally {
        loading.value = false
      }
    }

    onMounted(() => {
      loadReportTypes()
    })

    return {
      activeTab,
      activeView,
      reportTypeOptions,
      loading
    }
  }
}
</script>

<style scoped>
.dashboard {
  height: 100vh;
  display: flex;
  flex-direction: column;
}

.header {
  padding: 16px;
  background-color: #fff;
  border-bottom: 1px solid #eee;
  position: relative;
}

.header h1 {
  margin: 0;
  font-size: 24px;
  color: #333;
  text-align: center;
}

.selector-group {
  position: absolute;
  right: 16px;
  top: 50%;
  transform: translateY(-50%);
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.selector-title {
  font-size: 12px;
  color: #666;
  margin-bottom: 2px;
}

.report-type-selector {
  width: 200px;
}

.content {
  flex: 1;
  overflow: auto;
  padding: 16px;
  background-color: #f5f5f5;
}

:deep(.n-tabs-nav) {
  margin-bottom: 16px;
}

:deep(.n-tab-pane) {
  padding: 0;
  width: 100%;
}

:deep(.n-tabs-tab) {
  padding: 12px 20px;
  font-size: 14px;
  font-weight: 500;
}

:deep(.n-tabs-tab--active) {
  font-weight: 600;
}

:deep(.n-tabs-wrapper) {
  width: 100%;
}

:deep(.n-tabs-content) {
  width: 100%;
}
</style> 