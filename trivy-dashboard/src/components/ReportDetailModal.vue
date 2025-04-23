<template>
  <n-modal :show="show" @update:show="$emit('update:show', $event)" style="width: 80%">
    <n-card :title="reportTitle" :bordered="false" size="huge">
      <div v-if="report">
        <div class="report-summary">
          <h2>Summary</h2>
          <n-descriptions bordered>
            <!-- Dynamic summary fields based on report type -->
            <template v-for="field in summaryFields" :key="field.label">
              <n-descriptions-item :label="field.label">
                <template v-if="field.type === 'date'">
                  {{ formatDate(field.value) }}
                </template>
                <template v-else-if="field.type === 'image'">
                  {{ formatImage(field.value) }}
                </template>
                <template v-else-if="field.type === 'os' && field.value">
                  {{ field.value.name }} ({{ field.value.family }})
                </template>
                <template v-else-if="field.type === 'scanner' && field.value">
                  {{ field.value.name }} {{ field.value.version }}
                </template>
                <template v-else>
                  {{ field.value || 'N/A' }}
                </template>
              </n-descriptions-item>
            </template>
          </n-descriptions>

          <!-- Show severity summary for vulnerability and config audit reports -->
          <template v-if="isVulnerabilityReport() || isConfigAuditReport() || isExposedSecretReport()">
            <h3>{{ isVulnerabilityReport() ? 'Vulnerability' : isConfigAuditReport() ? 'Config Audit' : 'Exposed Secret' }} Summary</h3>
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
          </template>
        </div>

        <!-- Dynamic detail section title based on report type -->
        <h3>
          {{
            isVulnerabilityReport() ? 'Vulnerabilities' :
            isConfigAuditReport() ? 'Config Audit Results' :
            isExposedSecretReport() ? 'Exposed Secrets' :
            isSbomReport() ? 'Components' :
            'Details'
          }}
        </h3>

        <!-- Use dynamic columns and data based on report type -->
        <n-data-table
          :columns="detailColumns"
          :data="detailItems"
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
import { h, computed } from 'vue'
import { NButton, NModal, NCard, NDataTable, NDescriptions, NDescriptionsItem, NTag } from 'naive-ui'
import { formatDate, formatImage } from '../utils/formatters'
import {
  getReportDetailTitle,
  getReportDetailColumns,
  getReportDetailItems,
  getReportSummaryFields,
  isVulnerabilityReport,
  isConfigAuditReport,
  isExposedSecretReport,
  isSbomReport
} from '../utils/reportTypeUtils'

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
    },
    reportType: {
      type: String,
      default: 'vulnerabilityreports'
    }
  },
  emits: ['update:show'],
  setup(props) {
    // Get the report title based on report type
    const reportTitle = computed(() => getReportDetailTitle(props.reportType))

    // Get the detail items based on report type
    const detailItems = computed(() => getReportDetailItems(props.report, props.reportType))

    // Get the summary fields based on report type
    const summaryFields = computed(() => getReportSummaryFields(props.report, props.reportType))

    // Define columns based on report type
    const detailColumns = computed(() => {
      const columns = getReportDetailColumns(props.reportType)

      // Transform the columns to use h function for rendering
      return columns.map(column => {
        if (column.render && column.render.type === 'function') {
          return column
        }

        // If the column has a render function that returns an object with type
        if (column.render) {
          const originalRender = column.render
          column.render = (row) => {
            const result = originalRender(row)
            if (result.type === 'tag') {
              const colorMap = {
                'CRITICAL': 'error',
                'HIGH': '#ff7800',
                'MEDIUM': 'warning',
                'LOW': 'success',
                'UNKNOWN': 'default'
              }

              const type = colorMap[result.text] || 'default'

              return h(NTag, { type }, { default: () => result.text })
            } else if (result.type === 'link') {
              return h('a', { href: result.link, target: '_blank' }, result.text)
            } else {
              return result.text || ''
            }
          }
        }

        return column
      })
    })

    // Legacy vulnerability columns for backward compatibility
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
          const colorMap = {
            'CRITICAL': 'error',
            'HIGH': '#ff7800',
            'MEDIUM': 'warning',
            'LOW': 'success',
            'UNKNOWN': 'default'
          }

          const type = colorMap[row.severity] || 'default'

          return h(
            NTag,
            { type },
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
      formatImage,
      reportTitle,
      detailItems,
      detailColumns,
      summaryFields,
      isVulnerabilityReport: () => isVulnerabilityReport(props.reportType),
      isConfigAuditReport: () => isConfigAuditReport(props.reportType),
      isExposedSecretReport: () => isExposedSecretReport(props.reportType),
      isSbomReport: () => isSbomReport(props.reportType)
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
  text-align: center;
  padding: 10px;
  border-radius: 4px;
  min-width: 80px;
}
.vuln-count.critical {
  background-color: #fff1f0;
  color: #cf1322;
}
.vuln-count.high {
  background-color: #fff7e6;
  color: #d46b08;
}
.vuln-count.medium {
  background-color: #e6f7ff;
  color: #1890ff;
}
.vuln-count.low {
  background-color: #f6ffed;
  color: #52c41a;
}
.vuln-count.unknown {
  background-color: #f5f5f5;
  color: #8c8c8c;
}
.vuln-count .count {
  font-size: 24px;
  font-weight: bold;
}
.vuln-count .label {
  font-size: 12px;
  margin-top: 4px;
}
</style>