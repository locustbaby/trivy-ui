<template>
  <div class="dashboard-container">
    <h1>Trivy Dashboard</h1>
    
    <div class="tabs-container">
      <n-tabs type="line" animated>
        <n-tab-pane name="reports" tab="Vulnerability Reports">
          <TrivyReport />
        </n-tab-pane>
        <n-tab-pane name="clusters" tab="Clusters Management">
          <ClusterManager />
        </n-tab-pane>
      </n-tabs>
    </div>
  </div>
</template>

<script>
import { NTabs, NTabPane } from 'naive-ui'
import TrivyReport from './TrivyReport.vue'
import ClusterManager from './ClusterManager.vue'

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
  position: fixed;
  top: 30px;
  left: 0;
  right: 0;
  text-align: center;
  font-size: 24px;
  font-weight: 500;
  z-index: 100;
  background-color: #fff;
  padding: 10px 0;
}

.tabs-container {
  position: fixed;
  top: 80px;
  left: 0;
  right: 0;
  z-index: 99;
  background-color: white;
  padding: 10px;
  width: 90%;
  margin: 0 auto;
}

.dashboard-container {
  padding-top: 140px;
  width: 90%;
  margin: 0 auto;
}
</style> 