<template>
  <n-modal :show="show" @update:show="$emit('update:show', $event)" style="width: 80%">
    <n-card title="Vulnerability Report Details" :bordered="false" size="huge">
      <div v-if="report">
        <div class="report-summary">
          <h2>Summary</h2>
          <n-descriptions bordered>
            <n-descriptions-item label="Name">{{ report.metadata?.name }}</n-descriptions-item>
            <n-descriptions-item label="Namespace">{{ report.metadata?.namespace }}</n-descriptions-item>
            <n-descriptions-item label="Created">{{ formatDate(report.metadata?.creationTimestamp) }}</n-descriptions-item>
            <n-descriptions-item label="Image">{{ formatImage(report.report?.artifact) }}</n-descriptions-item>
            <n-descriptions-item label="OS">{{ report.report?.os?.name }} ({{ report.report?.os?.family }})</n-descriptions-item>
            <n-descriptions-item label="Scanner">{{ report.report?.scanner?.name }} {{ report.report?.scanner?.version }}</n-descriptions-item>
          </n-descriptions>

          <h3>Vulnerability Summary</h3>
          <div class="vuln-summary">
            <div class="vuln-count critical">
              <div class="count">{{ report.report?.summary?.criticalCount || 0 }}</div>
              <div class="label">Critical</div>
            </div>
            <div class="vuln-count high">
              <div class="count">{{ report.report?.summary?.highCount || 0 }}</div>
              <div class="label">High</div>
            </div>
            <div class="vuln-count medium">
              <div class="count">{{ report.report?.summary?.mediumCount || 0 }}</div>
              <div class="label">Medium</div>
            </div>
            <div class="vuln-count low">
              <div class="count">{{ report.report?.summary?.lowCount || 0 }}</div>
              <div class="label">Low</div>
            </div>
            <div class="vuln-count unknown">
              <div class="count">{{ report.report?.summary?.unknownCount || 0 }}</div>
              <div class="label">Unknown</div>
            </div>
          </div>
        </div>

        <h3>Vulnerabilities</h3>
        <n-data-table
          :columns="vulnerabilityColumns"
          :data="report.report?.vulnerabilities || []"
          :pagination="{ pageSize: 10 }"
          :bordered="true"
          striped
        />
      </div>
      <template #footer>
        <n-button @click="$emit('update:show', false)">Close</n-button>
      </template>
    </n-card>
  </n-modal>
</template>

<script>
import { h } from 'vue'
import { NButton, NModal, NCard, NDataTable, NDescriptions, NDescriptionsItem, NTag } from 'naive-ui'
import { formatDate, formatImage } from '../utils/formatters'

export default {
  components: {
    NModal, 
    NCard, 
    NButton,
    NDataTable,
    NDescriptions,
    NDescriptionsItem
  },
  props: {
    show: {
      type: Boolean,
      default: false
    },
    report: {
      type: Object,
      default: null
    }
  },
  emits: ['update:show'],
  setup() {
    const vulnerabilityColumns = [
      {
        title: 'ID',
        key: 'vulnerabilityID',
        sorter: 'default',
        render: (row) => {
          const link = row.primaryLink || `https://avd.aquasec.com/nvd/${row.vulnerabilityID.toLowerCase()}`
          return h('a', { href: link, target: '_blank' }, row.vulnerabilityID)
        }
      },
      {
        title: 'Severity',
        key: 'severity',
        sorter: (a, b) => {
          const severityOrder = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, UNKNOWN: 1 }
          return severityOrder[a.severity] - severityOrder[b.severity]
        },
        render: (row) => {
          const color = {
            'CRITICAL': 'error',
            'HIGH': '#ff7800',
            'MEDIUM': 'warning',
            'LOW': 'success',
            'UNKNOWN': 'default'
          }[row.severity] || 'default'
          
          return h(
            NTag,
            { type: 'info', color },
            { default: () => row.severity }
          )
        }
      },
      {
        title: 'Resource',
        key: 'resource',
        sorter: 'default'
      },
      {
        title: 'Installed Version',
        key: 'installedVersion'
      },
      {
        title: 'Fixed Version',
        key: 'fixedVersion'
      },
      {
        title: 'Title',
        key: 'title',
        ellipsis: {
          tooltip: true
        }
      }
    ]

    return {
      vulnerabilityColumns,
      formatDate,
      formatImage
    }
  }
}
</script>

<style scoped>
.report-summary {
  margin-bottom: 20px;
}
.vuln-summary {
  display: flex;
  margin: 10px 0 20px;
  gap: 15px;
}
.vuln-count {
  padding: 10px;
  border-radius: 4px;
  min-width: 80px;
  text-align: center;
}
.vuln-count .count {
  font-size: 24px;
  font-weight: bold;
}
.vuln-count .label {
  font-size: 14px;
}
.vuln-count.critical {
  background-color: #ffebee;
  color: #c62828;
}
.vuln-count.high {
  background-color: #fff3e0;
  color: #e65100;
}
.vuln-count.medium {
  background-color: #fff8e1;
  color: #f57f17;
}
.vuln-count.low {
  background-color: #e8f5e9;
  color: #2e7d32;
}
.vuln-count.unknown {
  background-color: #f5f5f5;
  color: #616161;
}
</style>