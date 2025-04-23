<template>
  <div class="cluster-manager">
    <div class="table-container">
      <div class="header">
        <div class="controls">
          <div class="left-controls">
            <n-button type="primary" @click="handleAddCluster" class="add-cluster-btn" title="Add Cluster">
              <template #icon>
                <n-icon><AddOutline /></n-icon>
              </template>
            </n-button>
          </div>
          <div class="right-controls">
            <n-button @click="refreshData" type="warning" class="refresh-btn" title="Refresh">
              <template #icon>
                <n-icon><RefreshOutline /></n-icon>
              </template>
            </n-button>
          </div>
        </div>
      </div>

      <div v-if="error" class="error">{{ error }}</div>

      <div class="table-wrapper">
        <div v-if="loading" class="loading">Loading data...</div>

        <div v-if="clusters.length === 0 && !loading" class="no-clusters">
          No clusters found. Add a cluster to get started.
        </div>

        <n-data-table
          v-if="clusters.length > 0"
          :columns="columns"
          :data="clusters"
          :pagination="pagination"
          :bordered="false"
          stripe
          class="cluster-table"
        />
      </div>
    </div>

    <!-- Add Cluster Modal -->
    <n-modal
      v-model:show="showAddClusterModal"
      preset="card"
      title="Add New Cluster"
      class="cluster-modal"
    >
      <n-form
        ref="formRef"
        :model="clusterForm"
        :rules="rules"
        label-placement="left"
        label-width="100px"
      >
        <n-form-item label="Cluster Name" path="name">
          <n-input v-model:value="clusterForm.name" placeholder="Enter cluster name" />
        </n-form-item>

        <n-form-item label="KubeConfig" path="kubeConfig">
          <n-input
            v-model:value="clusterForm.kubeConfig"
            type="textarea"
            placeholder="Paste your kubeconfig here"
            :rows="10"
          />
        </n-form-item>
      </n-form>

      <template #footer>
        <n-space justify="end">
          <n-button @click="cancelAddCluster">Cancel</n-button>
          <n-button type="primary" @click="submitAddCluster" :loading="loading">
            Add Cluster
          </n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- Delete Confirmation Modal -->
    <n-modal
      v-model:show="showDeleteModal"
      preset="dialog"
      title="Confirm Deletion"
      positive-text="Delete"
      negative-text="Cancel"
      @positive-click="confirmDelete"
      @negative-click="cancelDelete"
    >
      Are you sure you want to delete the cluster "{{ clusterToDelete }}"?
    </n-modal>
  </div>
</template>

<script>
import { ref, reactive, h, onMounted, watch } from 'vue'
import {
  NButton,
  NInput,
  NIcon,
  NDataTable,
  NModal,
  NForm,
  NFormItem,
  NSpace,
  NSwitch
} from 'naive-ui'
import { RefreshOutline, AddOutline, TrashOutline } from '@vicons/ionicons5'
import { useClusterData } from '../composables/useClusterData'
import { useMessage } from 'naive-ui'

export default {
  name: 'ClusterManager',
  components: {
    NButton,
    NInput,
    NIcon,
    NDataTable,
    NModal,
    NForm,
    NFormItem,
    NSpace,
    NSwitch,
    RefreshOutline,
    AddOutline,
    TrashOutline
  },
  setup() {
    const message = useMessage()
    const formRef = ref(null)

    const {
      loading,
      error,
      clusters,
      showAddClusterModal,
      loadClusters,
      createCluster,
      removeCluster,
      updateCluster,
      clearCache,
      openAddClusterModal,
      closeAddClusterModal
    } = useClusterData()

    // Form for adding new clusters
    const clusterForm = reactive({
      name: '',
      kubeConfig: ''
    })

    // Form validation rules
    const rules = {
      name: [
        { required: true, message: 'Please enter a cluster name', trigger: 'blur' },
        { min: 3, message: 'Cluster name must be at least 3 characters', trigger: 'blur' }
      ],
      kubeConfig: [
        { required: true, message: 'Please provide the kubeconfig content', trigger: 'blur' }
      ]
    }

    // Pagination settings
    const pagination = {
      pageSize: 10
    }

    // Delete confirmation
    const showDeleteModal = ref(false)
    const clusterToDelete = ref('')

    // Table columns definition
    const columns = [
      {
        title: 'Cluster Name',
        key: 'name',
        width: 300,
        sorter: (a, b) => a.name.localeCompare(b.name)
      },
      {
        title: 'Enabled',
        key: 'enable',
        width: 200,
        render(row) {
          return h(
            NSwitch,
            {
              value: row.enable,
              onUpdateValue: (value) => handleToggleCluster(row.name, value)
            }
          )
        }
      },
      {
        title: 'Actions',
        key: 'actions',
        width: 200,
        render(row) {
          return h(
            NButton,
            {
              size: 'small',
              type: 'error',
              onClick: () => handleDeleteCluster(row.name)
            },
            {
              default: () => 'Delete',
              icon: () => h(TrashOutline)
            }
          )
        }
      }
    ]

    // Load clusters on component mount
    onMounted(() => {
      console.log('ClusterManager mounted, loading clusters...')
      loadClusters()
    })

    // Handle add cluster button click
    function handleAddCluster() {
      resetForm()
      openAddClusterModal()
    }

    // Reset form fields
    function resetForm() {
      clusterForm.name = ''
      clusterForm.kubeConfig = ''
      if (formRef.value) {
        formRef.value.restoreValidation()
      }
    }

    // Cancel adding a cluster
    function cancelAddCluster() {
      closeAddClusterModal()
      resetForm()
    }

    // Submit the cluster form
    async function submitAddCluster() {
      if (!formRef.value) return

      try {
        await formRef.value.validate()

        const success = await createCluster({
          name: clusterForm.name,
          kubeConfig: clusterForm.kubeConfig
        })

        if (success) {
          message.success('Cluster added successfully')
          closeAddClusterModal()
          resetForm()
        }
      } catch (err) {
        console.error('Form validation failed:', err)
      }
    }

    // Handle delete cluster button click
    function handleDeleteCluster(name) {
      clusterToDelete.value = name
      showDeleteModal.value = true
    }

    // Confirm cluster deletion
    async function confirmDelete() {
      if (!clusterToDelete.value) return

      const success = await removeCluster(clusterToDelete.value)

      if (success) {
        message.success('Cluster deleted successfully')

        // 立即更新本地缓存中的集群列表
        const cachedClusters = JSON.parse(localStorage.getItem('trivy-clusters') || '[]')
        const updatedClusters = cachedClusters.filter(c => c.name !== clusterToDelete.value)
        localStorage.setItem('trivy-clusters', JSON.stringify(updatedClusters))

        // 重新加载集群列表
        await loadClusters()

        // 触发全局事件，通知其他组件集群已被删除
        window.dispatchEvent(new CustomEvent('cluster-deleted', {
          detail: { clusterName: clusterToDelete.value }
        }))
      }

      showDeleteModal.value = false
      clusterToDelete.value = ''
    }

    // Cancel cluster deletion
    function cancelDelete() {
      showDeleteModal.value = false
      clusterToDelete.value = ''
    }

    // Refresh clusters data
    function refreshData() {
      clearCache()
      loadClusters()
    }

    // Handle toggle cluster enabled status
    async function handleToggleCluster(name, enable) {
      try {
        loading.value = true
        error.value = null

        // Find the cluster in the list
        const cluster = clusters.value.find(c => c.name === name)
        if (!cluster) {
          message.error('Cluster not found')
          return
        }

        // Update the cluster's enable status
        const success = await updateCluster({
          name: cluster.name,
          enable: enable
        })

        if (success) {
          message.success(`Cluster ${enable ? 'enabled' : 'disabled'} successfully`)

          // 立即更新本地缓存中的集群状态
          const cachedClusters = JSON.parse(localStorage.getItem('trivy-clusters') || '[]')
          const updatedClusters = cachedClusters.map(c => {
            if (c.name === name) {
              return { ...c, enable: enable }
            }
            return c
          })
          localStorage.setItem('trivy-clusters', JSON.stringify(updatedClusters))

          // 重新加载集群列表
          await loadClusters()

          // 触发全局事件，通知其他组件集群状态已更改
          window.dispatchEvent(new CustomEvent('cluster-status-changed', {
            detail: { clusterName: name, enabled: enable }
          }))

          // 如果集群被禁用，清空相关数据
          if (!enable) {
            // 清空该集群的所有缓存数据
            const cacheKeys = Object.keys(localStorage).filter(key => key.includes(name))
            cacheKeys.forEach(key => localStorage.removeItem(key))
          }
        }
      } catch (err) {
        error.value = `Failed to ${enable ? 'enable' : 'disable'} cluster: ${err.message}`
        console.error(err)
        message.error(`Failed to ${enable ? 'enable' : 'disable'} cluster`)
      } finally {
        loading.value = false
      }
    }

    return {
      loading,
      error,
      clusters,
      columns,
      pagination,
      showAddClusterModal,
      clusterForm,
      rules,
      formRef,
      handleAddCluster,
      cancelAddCluster,
      submitAddCluster,
      showDeleteModal,
      clusterToDelete,
      handleDeleteCluster,
      confirmDelete,
      cancelDelete,
      refreshData,
      handleToggleCluster
    }
  }
}
</script>

<style scoped>
.cluster-manager {
  padding: 20px;
  width: 100%;
  box-sizing: border-box;
  display: flex;
  flex-direction: column;
}

.table-container {
  flex: 1;
  width: 100%;
  min-width: 800px;
  max-width: 1200px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
  position: relative;
}

.controls {
  display: flex;
  justify-content: space-between;
  width: 100%;
  background: transparent;
  position: relative;
}

.left-controls, .right-controls {
  display: flex;
  gap: 8px;
  position: relative;
  z-index: 2;
}

.add-cluster-btn, .refresh-btn {
  width: 36px;
  height: 36px;
  padding: 0;
  border-radius: 8px;
  transition: all 0.3s ease;
  position: relative;
  z-index: 2;
}

.add-cluster-btn:hover, .refresh-btn:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.add-cluster-btn .n-icon, .refresh-btn .n-icon {
  font-size: 20px;
}

.cluster-list {
  background: #fff;
  border-radius: 12px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
  overflow: hidden;
  width: 100%;
  min-height: 400px;
}

.table-wrapper {
  width: 100%;
  min-height: 400px;
  background: #fff;
  border-radius: 8px;
  position: relative;
  display: flex;
  flex-direction: column;
}

.loading, .no-clusters {
  width: 100%;
  min-height: 400px;
  display: flex;
  align-items: center;
  justify-content: center;
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: #fff;
  border-radius: 8px;
  z-index: 2;
}

.loading {
  font-style: italic;
}

.no-clusters {
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

.cluster-table {
  width: 100%;
  position: relative;
  z-index: 1;
}

.cluster-table :deep(.n-data-table-wrapper) {
  width: 100%;
  position: relative;
  z-index: 1;
}

.cluster-table :deep(.n-data-table) {
  width: 100%;
  table-layout: fixed;
  position: relative;
  z-index: 1;
}

.cluster-table :deep(.n-data-table-td) {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  padding: 12px 16px;
}

.cluster-table :deep(.n-data-table-th) {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  padding: 12px 16px;
  background-color: #fafafa;
}

.cluster-table :deep(.n-data-table-tr) {
  width: 100%;
}

.cluster-table :deep(.n-data-table-th-column) {
  width: 100%;
}

.cluster-table :deep(.n-data-table-td.name),
.cluster-table :deep(.n-data-table-th.name) {
  width: 400px;
}

.cluster-table :deep(.n-data-table-td.enabled),
.cluster-table :deep(.n-data-table-th.enabled) {
  width: 200px;
}

.cluster-table :deep(.n-data-table-td.actions),
.cluster-table :deep(.n-data-table-th.actions) {
  width: 200px;
}

.cluster-modal {
  max-width: 700px;
}
</style>