<template>
  <div class="cluster-manager">
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
    
    <div v-if="loading" class="loading">Loading data...</div>
    <div v-if="error" class="error">{{ error }}</div>
    
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
import { ref, reactive, h, onMounted } from 'vue'
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
        sorter: (a, b) => a.name.localeCompare(b.name)
      },
      {
        title: 'Enabled',
        key: 'enable',
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
      
      formRef.value.validate(async (errors) => {
        if (errors) {
          message.error('Please correct the form errors')
          return
        }
        
        try {
          loading.value = true
          error.value = null
          
          const success = await createCluster({
            name: clusterForm.name,
            kubeConfig: clusterForm.kubeConfig
          })
          
          if (success) {
            message.success('Cluster added successfully')
            resetForm()
            closeAddClusterModal()
          } else {
            // 显示具体的错误信息
            const errorMsg = error.value || 'Failed to add cluster'
            message.error(errorMsg)
            console.error('Error adding cluster:', errorMsg)
          }
        } catch (err) {
          const errorMsg = err.message || 'Failed to add cluster'
          message.error(errorMsg)
          console.error('Error adding cluster:', err)
        } finally {
          loading.value = false
        }
      })
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
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}

.controls {
  display: flex;
  justify-content: space-between;
  width: 100%;
  margin-bottom: 20px;
}

.left-controls, .right-controls {
  display: flex;
  gap: 8px;
}

.add-cluster-btn, .refresh-btn {
  width: 36px;
  height: 36px;
  padding: 0;
  border-radius: 8px;
  transition: all 0.3s ease;
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
}

.cluster-item {
  padding: 16px 24px;
  border-bottom: 1px solid #f0f0f0;
  transition: background-color 0.3s ease;
}

.cluster-item:last-child {
  border-bottom: none;
}

.cluster-item:hover {
  background-color: #f9f9f9;
}

.cluster-info {
  display: flex;
  align-items: center;
  gap: 12px;
}

.cluster-name {
  font-size: 16px;
  font-weight: 500;
  color: #333;
}

.cluster-status {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
}

.cluster-status.enabled {
  background-color: #e6f7e6;
  color: #52c41a;
}

.cluster-status.disabled {
  background-color: #fff1f0;
  color: #ff4d4f;
}

.cluster-actions {
  display: flex;
  gap: 8px;
}

.action-btn {
  padding: 6px;
  border-radius: 6px;
  transition: all 0.3s ease;
}

.action-btn:hover {
  background-color: #f5f5f5;
}

.action-btn .n-icon {
  font-size: 18px;
}

.action-btn.delete:hover {
  color: #ff4d4f;
  background-color: #fff1f0;
}

.action-btn.edit:hover {
  color: #1890ff;
  background-color: #e6f7ff;
}

.action-btn.toggle:hover {
  color: #52c41a;
  background-color: #e6f7e6;
}

.modal-content {
  padding: 24px;
}

.form-item {
  margin-bottom: 24px;
}

.form-item label {
  display: block;
  margin-bottom: 8px;
  font-weight: 500;
  color: #333;
}

.form-item input {
  width: 100%;
  padding: 8px 12px;
  border: 1px solid #d9d9d9;
  border-radius: 6px;
  transition: all 0.3s ease;
}

.form-item input:focus {
  border-color: #1890ff;
  box-shadow: 0 0 0 2px rgba(24, 144, 255, 0.2);
  outline: none;
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 24px;
  padding-top: 16px;
  border-top: 1px solid #f0f0f0;
}

.modal-footer button {
  min-width: 80px;
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
.no-clusters {
  padding: 20px;
  text-align: center;
  background-color: #f5f5f5;
  border-radius: 4px;
  margin-bottom: 20px;
}
.cluster-modal {
  max-width: 700px;
}

.cluster-table {
  width: 100%;
  min-width: 800px;
  margin: 0 auto;
}

.cluster-table :deep(.n-data-table-td) {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.cluster-table :deep(.n-data-table-th) {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
</style> 