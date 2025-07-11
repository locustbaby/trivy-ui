<template>
  <div class="p-6 space-y-6">
    <Card>
      <CardHeader>
        <CardTitle>Trivy Dashboard</CardTitle>
        <CardDescription>Multi-cluster, multi-type security reports</CardDescription>
      </CardHeader>
      <CardContent>
        <div class="flex flex-wrap gap-4 mb-4 items-center">
          <!-- Cluster Selector -->
          <Select v-model="selectedCluster">
            <SelectTrigger class="w-40">
              <SelectValue placeholder="Select Cluster" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem v-for="c in clusters" :key="c.name" :value="c.name">{{ c.name }}</SelectItem>
            </SelectContent>
          </Select>
          <!-- Namespace Selector -->
          <Select v-model="selectedNamespace">
            <SelectTrigger class="w-40">
              <SelectValue placeholder="Select Namespace" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem v-for="ns in namespaces" :key="ns" :value="ns">{{ ns }}</SelectItem>
            </SelectContent>
          </Select>
          <!-- Report Type Selector -->
          <Select v-model="selectedReportType">
            <SelectTrigger class="w-56">
              <SelectValue placeholder="Select Report Type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem v-for="type in reportTypes" :key="type" :value="type">{{ type }}</SelectItem>
            </SelectContent>
          </Select>
          <!-- Refresh Button -->
          <Button @click="refreshReports">Refresh</Button>
        </div>
        <!-- Reports Table 搜索框 -->
        <div class="flex items-center gap-2 mb-2 justify-center">
          <input
            v-model="mainSearchText"
            type="text"
            placeholder="Search Name, Repository, Tag, Scanner..."
            class="border rounded px-2 py-1 w-64 text-sm focus:outline-none focus:ring"
          />
        </div>
        <!-- Reports Table -->
        <div v-if="loading">
          <Skeleton class="h-10 w-full mb-2" v-for="i in pageSize" :key="i" />
        </div>
        <Table v-else-if="paginatedReports.length">
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Summary</TableHead>
              <TableHead>Repository</TableHead>
              <TableHead>Tag</TableHead>
              <TableHead>Scanner</TableHead>
              <TableHead>Age</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="report in paginatedReports" :key="report.name" class="cursor-pointer hover:bg-accent" @click="showDetail(report)">
              <TableCell>{{ report.data.meta.name }}</TableCell>
              <TableCell>
                <div class="flex gap-2">
                  <Badge
                    v-for="(val, key) in report.data.summary"
                    :key="key"
                    :variant="key.toLowerCase()"
                  >
                    {{ key }}: {{ val }}
                  </Badge>
                </div>
              </TableCell>
              <TableCell>{{ report.data.repository }}</TableCell>
              <TableCell>{{ report.data.tag }}</TableCell>
              <TableCell>{{ report.data.scanner }}</TableCell>
              <TableCell>{{ report.data.age }}</TableCell>
            </TableRow>
          </TableBody>
        </Table>
        <div v-else-if="!loading" class="text-center text-muted-foreground py-8">No reports found.</div>
        <SmartPagination
          v-if="!loading && total > pageSize"
          :page="page"
          :items-per-page="pageSize"
          :total="total"
          @update:page="page = $event"
          class="mt-4"
        />
        <!-- Report Detail Dialog -->
        <Dialog :open="detailOpen" @update:open="detailOpen = $event">
          <DialogContent class="max-w-5xl max-h-[80vh] overflow-auto rounded-2xl shadow-2xl p-6 bg-white dark:bg-zinc-900">
            <DialogHeader>
              <DialogTitle>Report Detail: {{ selectedReport?.data?.metadata?.name }}</DialogTitle>
            </DialogHeader>
            <div v-if="detailLoading" class="text-center py-8">Loading...</div>
            <div v-else>
              <div class="text-xs text-muted-foreground mb-2">
                Type: {{ selectedReportType }} | Path: {{ reportData ? 'report' : 'none' }}
              </div>
              <template v-if="selectedReportType && selectedReportType.toLowerCase().includes('vuln') && reportData">
                <!-- Artifact/OS/Scanner/Summary -->
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                  <div class="bg-muted rounded p-3">
                    <div class="font-semibold mb-1">Artifact</div>
                    <div>Repository: <span class="font-mono">{{ reportData.artifact.repository }}</span></div>
                    <div>Tag: <span class="font-mono">{{ reportData.artifact.tag }}</span></div>
                    <div>Digest: <span class="font-mono break-all">{{ reportData.artifact.digest }}</span></div>
                  </div>
                  <div class="bg-muted rounded p-3">
                    <div class="font-semibold mb-1">Scanner</div>
                    <div>Name: {{ reportData.scanner.name }}</div>
                    <div>Vendor: {{ reportData.scanner.vendor }}</div>
                    <div>Version: {{ reportData.scanner.version }}</div>
                  </div>
                  <div class="bg-muted rounded p-3">
                    <div class="font-semibold mb-1">OS</div>
                    <div>Family: {{ reportData.os.family }}</div>
                    <div>Name: {{ reportData.os.name }}</div>
                  </div>
                  <div class="bg-muted rounded p-3">
                    <div class="font-semibold mb-1">Summary</div>
                    <div class="flex flex-wrap gap-2 mt-1">
                      <Badge
                        v-for="sev in severityOrder"
                        :key="sev"
                        :variant="sev"
                        :class="[
                          'cursor-pointer select-none',
                          activeSeverity === sev ? 'ring-2 ring-offset-2 ring-primary scale-105' : '',
                        ]"
                        @click.stop="toggleSeverityFilter(sev)"
                      >
                        {{ sev.charAt(0).toUpperCase() + sev.slice(1) }}: {{ reportData.summary[severityKeyMap[sev]] }}
                      </Badge>
                    </div>
                  </div>
                </div>
                <!-- Vulnerabilities Table with Pagination -->
                <div class="mb-2 font-semibold border-t pt-4">Vulnerabilities</div>
                <div class="flex items-center gap-2 mb-2">
                  <input
                    v-model="searchText"
                    type="text"
                    placeholder="Search CVE, Title, Package..."
                    class="border rounded px-2 py-1 w-64 text-sm focus:outline-none focus:ring"
                  />
                  <span v-if="activeSeverity" class="text-xs text-muted-foreground">Filtering: {{ activeSeverity }}</span>
                </div>
                <div class="overflow-x-auto custom-scrollbar">
                  <Table v-if="Array.isArray(reportData.vulnerabilities) && reportData.vulnerabilities.length">
                    <TableHeader class="bg-muted">
                      <TableRow>
                        <TableHead class="font-bold">CVE</TableHead>
                        <TableHead class="font-bold">Title</TableHead>
                        <TableHead class="font-bold">Package</TableHead>
                        <TableHead class="font-bold">Severity</TableHead>
                        <TableHead class="font-bold">Installed</TableHead>
                        <TableHead class="font-bold">Fixed</TableHead>
                        <TableHead class="font-bold">Score</TableHead>
                        <TableHead class="font-bold">Link</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      <TableRow v-for="vuln in pagedVulns" :key="vuln.vulnerabilityID" class="hover:bg-accent/50 transition-colors">
                        <TableCell>{{ vuln.vulnerabilityID }}</TableCell>
                        <TableCell>{{ vuln.title }}</TableCell>
                        <TableCell>{{ vuln.resource }}</TableCell>
                        <TableCell>
                          <Badge :variant="vuln.severity === 'CRITICAL' ? 'destructive' : 'secondary'">{{ vuln.severity }}</Badge>
                        </TableCell>
                        <TableCell>{{ vuln.installedVersion }}</TableCell>
                        <TableCell>{{ vuln.fixedVersion }}</TableCell>
                        <TableCell>{{ vuln.score }}</TableCell>
                        <TableCell>
                          <a v-if="vuln.primaryLink" :href="vuln.primaryLink" target="_blank" class="text-blue-600 underline">Link</a>
                        </TableCell>
                      </TableRow>
                    </TableBody>
                  </Table>
                  <div v-else class="text-muted-foreground">No vulnerabilities found.</div>
                </div>
                <SmartPagination
                  v-if="vulnTotalPages > 1"
                  :page="vulnPage"
                  :items-per-page="vulnPageSize"
                  :total="reportData.vulnerabilities.length"
                  @update:page="vulnPage = $event"
                  class="mt-2"
                />
              </template>
              <template v-else>
                <div class="overflow-auto max-h-[60vh] bg-muted rounded p-4 custom-scrollbar">
                  <pre class="text-xs whitespace-pre-wrap">{{ formatJson(selectedReport?.data) }}</pre>
                </div>
              </template>
            </div>
            <DialogFooter>
              <Button @click="closeDetail">Close</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </CardContent>
    </Card>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch } from 'vue';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '@/components/ui/table';
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '@/components/ui/select';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog';
import SmartPagination from '@/views/SmartPagination.vue'
import { fetchClusters, fetchNamespaces, fetchReportTypes, fetchReports, fetchReportDetails } from '@/api/trivy';

const clusters = ref([]);
const reportTypes = ref([]);
const selectedCluster = ref(localStorage.getItem('selectedCluster') || '');
const selectedNamespace = ref(localStorage.getItem('selectedNamespace') || '');
const selectedReportType = ref(localStorage.getItem('selectedReportType') || '');
const namespaces = ref([]);
const reports = ref([]);
const loading = ref(false);

// 分页
const page = ref(1);
const pageSize = 10;
const total = computed(() => reports.value.length);
const totalPages = computed(() => Math.ceil(total.value / pageSize));
const mainSearchText = ref('');
const filteredReports = computed(() => {
  if (!mainSearchText.value.trim()) return reports.value;
  const q = mainSearchText.value.trim().toLowerCase();
  return reports.value.filter(r =>
    (r.data.meta.name && r.data.meta.name.toLowerCase().includes(q)) ||
    (r.data.repository && r.data.repository.toLowerCase().includes(q)) ||
    (r.data.tag && r.data.tag.toLowerCase().includes(q)) ||
    (r.data.scanner && r.data.scanner.toLowerCase().includes(q))
  );
});
const paginatedReports = computed(() => {
  const start = (page.value - 1) * pageSize;
  return filteredReports.value.slice(start, start + pageSize);
});

// 详情弹窗
const selectedReport = ref(null);
const detailOpen = ref(false);
const detailLoading = ref(false);

const reportData = computed(() => {
  // 兼容 selectedReport.data.report 和 selectedReport.data.data.report
  return selectedReport?.value?.data?.report || selectedReport?.value?.data?.data?.report || null;
});

// 详情弹窗内漏洞分页
const vulnPage = ref(1);
const vulnPageSize = 10;
const severityOrder = ['critical', 'high', 'medium', 'low', 'unknown'];
const severityKeyMap = {
  critical: 'criticalCount',
  high: 'highCount',
  medium: 'mediumCount',
  low: 'lowCount',
  unknown: 'unknownCount',
};
const activeSeverity = ref('');
function toggleSeverityFilter(sev) {
  activeSeverity.value = activeSeverity.value === sev ? '' : sev;
  vulnPage.value = 1;
}
const searchText = ref('');
const filteredVulns = computed(() => {
  if (!reportData.value || !Array.isArray(reportData.value.vulnerabilities)) return [];
  let vulns = reportData.value.vulnerabilities;
  if (activeSeverity.value) {
    vulns = vulns.filter(v => v.severity && v.severity.toLowerCase() === activeSeverity.value);
  }
  if (searchText.value.trim()) {
    const q = searchText.value.trim().toLowerCase();
    vulns = vulns.filter(v =>
      (v.vulnerabilityID && v.vulnerabilityID.toLowerCase().includes(q)) ||
      (v.title && v.title.toLowerCase().includes(q)) ||
      (v.resource && v.resource.toLowerCase().includes(q))
    );
  }
  return vulns;
});
const pagedVulns = computed(() => {
  const start = (vulnPage.value - 1) * vulnPageSize;
  return filteredVulns.value.slice(start, start + vulnPageSize);
});
const vulnTotalPages = computed(() => Math.ceil(filteredVulns.value.length / vulnPageSize) || 1);

async function showDetail(report) {
  detailOpen.value = true;
  detailLoading.value = true;
  try {
    const type = selectedReportType.value;
    const cluster = selectedCluster.value;
    const namespace = selectedNamespace.value;
    const name = report.data.meta.name;
    const detail = await fetchReportDetails(type, cluster, namespace, name);
    selectedReport.value = { data: detail };
  } catch (e) {
    selectedReport.value = { data: { error: e.message } };
  } finally {
    detailLoading.value = false;
  }
}
function closeDetail() {
  detailOpen.value = false;
  selectedReport.value = null;
}
function formatJson(obj) {
  if (!obj) return '';
  return JSON.stringify(obj, null, 2);
}

// 主页 summary Badge 颜色映射
const severityColors = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-400 text-black',
  low: 'bg-blue-500 text-white',
  unknown: 'bg-gray-400 text-white',
};

async function loadClustersAndNamespaces(force = false) {
  loading.value = true;
  try {
    // Always fetch clusters if force or clusters is empty
    if (force || clusters.value.length === 0) {
      const clusterResp = await fetchClusters();
      clusters.value = (clusterResp.data || clusterResp) ?? [];
      if (clusters.value.length > 0) {
        if (!selectedCluster.value || !clusters.value.some(c => c.name === selectedCluster.value)) {
          selectedCluster.value = clusters.value[0].name;
        }
      } else {
        selectedCluster.value = '';
      }
    }
    // Always fetch namespaces if force or namespaces is empty
    if (selectedCluster.value && (force || namespaces.value.length === 0)) {
      const nsResp = await fetchNamespaces(selectedCluster.value);
      namespaces.value = (nsResp.data || nsResp) ?? [];
      if (namespaces.value.length > 0) {
        if (!selectedNamespace.value || !namespaces.value.includes(selectedNamespace.value)) {
          selectedNamespace.value = namespaces.value[0].name || namespaces.value[0];
        }
      } else {
        selectedNamespace.value = '';
      }
    }
  } finally {
    loading.value = false;
  }
}

onMounted(async () => {
  loading.value = true;
  try {
    await loadClustersAndNamespaces();
    const typeResp = await fetchReportTypes();
    reportTypes.value = typeResp.data || typeResp;
    if (reportTypes.value.length > 0) {
      if (!selectedReportType.value || !reportTypes.value.includes(selectedReportType.value)) {
        selectedReportType.value = reportTypes.value[0];
      }
    }
  } finally {
    loading.value = false;
  }
});

// 监听集群变化加载 namespace（即使只有一个 cluster 也会触发）
watch(selectedCluster, async (val) => {
  localStorage.setItem('selectedCluster', val || '');
  if (!val) {
    namespaces.value = [];
    selectedNamespace.value = '';
    return;
  }
  loading.value = true;
  try {
    const nsResp = await fetchNamespaces(val);
    namespaces.value = (nsResp.data || nsResp) ?? [];
    if (namespaces.value.length > 0) {
      if (!selectedNamespace.value || !namespaces.value.includes(selectedNamespace.value)) {
        selectedNamespace.value = namespaces.value[0].name || namespaces.value[0];
      }
    } else {
      selectedNamespace.value = '';
    }
  } finally {
    loading.value = false;
  }
});

watch(selectedNamespace, (val) => {
  localStorage.setItem('selectedNamespace', val || '');
});
watch(selectedReportType, (val) => {
  localStorage.setItem('selectedReportType', val || '');
});

// 监听选择变化加载报告
watch([selectedCluster, selectedNamespace, selectedReportType], async ([c, ns, type]) => {
  if (!c || !ns || !type) return;
  loading.value = true;
  try {
    const resp = await fetchReports(type, c, ns);
    reports.value = (resp.data || resp) ?? [];
    page.value = 1;
  } finally {
    loading.value = false;
  }
});

async function refreshReports() {
  // 如果 clusters/selectedCluster/selectedNamespace 为空，强制重新请求
  if (!clusters.value.length || !selectedCluster.value || !selectedNamespace.value) {
    await loadClustersAndNamespaces(true);
  }
  if (selectedCluster.value && selectedNamespace.value && selectedReportType.value) {
    loading.value = true;
    fetchReports(selectedReportType.value, selectedCluster.value, selectedNamespace.value, true).then(resp => {
      reports.value = (resp.data || resp) ?? [];
      page.value = 1;
      loading.value = false;
    });
  }
}

// 在每次弹窗打开时重置分页
watch(detailOpen, (open) => {
  if (open) vulnPage.value = 1;
});

// 搜索时自动跳转到第一页
watch(mainSearchText, () => {
  page.value = 1;
});
</script>

<style>
.custom-scrollbar {
  scrollbar-width: thin;
  scrollbar-color: #d1d5db #f9fafb;
}
.custom-scrollbar::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}
.custom-scrollbar::-webkit-scrollbar-thumb {
  background: #d1d5db;
  border-radius: 6px;
}
.custom-scrollbar::-webkit-scrollbar-track {
  background: #f9fafb;
  border-radius: 6px;
}
</style> 