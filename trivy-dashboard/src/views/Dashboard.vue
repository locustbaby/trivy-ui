<template>
  <div>
    <h1>Trivy Dashboard</h1>
    
    <n-tabs type="line" animated>
      <n-tab-pane name="reports" tab="Vulnerability Reports">
        <TrivyReport />
      </n-tab-pane>
      <n-tab-pane name="clusters" tab="Clusters Management">
        <ClusterManager />
      </n-tab-pane>
    </n-tabs>
  </div>
</template>

<script>
import { NTabs, NTabPane } from 'naive-ui'
import TrivyReport from './TrivyReport.vue'
import ClusterManager from '../components/ClusterManager.vue'

export default {
  name: 'Dashboard',
  components: {
    NTabs,
    NTabPane,
    TrivyReport,
    ClusterManager
  },
  setup() {
    return {}
  }
}
</script>

<style scoped>
h1 {
  margin-bottom: 20px;
}
</style> 