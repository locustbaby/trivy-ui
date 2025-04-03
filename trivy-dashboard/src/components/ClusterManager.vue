<template>
  <div class="cluster-manager">
    <h2>Clusters Management</h2>
    
    <div class="controls">
      <n-button @click="handleAddCluster" type="primary">
        <template #icon>
          <n-icon><AddOutline /></n-icon>
        </template>
        Add Cluster
      </n-button>
      <n-button @click="refreshData" type="warning" class="refresh-btn">
        <template #icon>
          <n-icon><RefreshOutline /></n-icon>
        </template>
        Refresh
      </n-button>
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
  NSpace 
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
        
        const success = await createCluster({
          name: clusterForm.name,
          kubeConfig: clusterForm.kubeConfig
        })
        
        if (success) {
          message.success('Cluster added successfully')
          resetForm()
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
      refreshData
    }
  }
}
</script>

<style scoped>
.cluster-manager {
  margin-top: 30px;
}
.controls {
  display: flex;
  margin-bottom: 20px;
  gap: 10px;
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
</style> 