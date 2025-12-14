package kubernetes

import (
	"context"
	"fmt"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"

	"trivy-ui/config"
	"trivy-ui/utils"
)

type CacheUpdater interface {
	SetReport(cluster, namespace, reportType, name string, report *Report)
	DeleteReport(cluster, namespace, reportType, name string)
}

type ReportInformerManager struct {
	mu           sync.RWMutex
	client       *Client
	informers    map[string]cache.SharedInformer
	clusterName  string
	ctx          context.Context
	cancel       context.CancelFunc
	cacheUpdater CacheUpdater
}

func NewReportInformerManager(client *Client, clusterName string, cacheUpdater CacheUpdater) *ReportInformerManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &ReportInformerManager{
		client:       client,
		informers:    make(map[string]cache.SharedInformer),
		clusterName:  clusterName,
		ctx:          ctx,
		cancel:       cancel,
		cacheUpdater: cacheUpdater,
	}
}

func (m *ReportInformerManager) Start() error {
	registry := config.GetGlobalRegistry()
	reports := registry.GetAllReports()

	if len(reports) == 0 {
		return fmt.Errorf("no report types discovered")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(
		m.client.dynamic,
		0,
		metav1.NamespaceAll,
		nil,
	)

	for _, reportType := range reports {
		group, version := parseAPIVersion(reportType.APIVersion)
		gvr := schema.GroupVersionResource{
			Group:    group,
			Version:  version,
			Resource: reportType.Name,
		}

		var informer cache.SharedInformer
		if reportType.Namespaced {

			informer = factory.ForResource(gvr).Informer()
		} else {

			informer = factory.ForResource(gvr).Informer()
		}

		informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				m.onAdd(reportType, obj)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				m.onUpdate(reportType, oldObj, newObj)
			},
			DeleteFunc: func(obj interface{}) {
				m.onDelete(reportType, obj)
			},
		})

		m.informers[reportType.Name] = informer
	}

	factory.Start(m.ctx.Done())

	// 异步等待 informer 同步，不阻塞应用启动
	go m.waitForSyncAndWarmup(reports)

	utils.LogInfo("Started informers for report types (syncing in background)", map[string]interface{}{"cluster": m.clusterName, "count": len(m.informers)})
	return nil
}

// waitForSyncAndWarmup 异步等待 informer 同步并加载现有资源
func (m *ReportInformerManager) waitForSyncAndWarmup(reports []config.ReportKind) {
	timeout := 60 * time.Second
	ctx, cancel := context.WithTimeout(m.ctx, timeout)
	defer cancel()

	m.mu.RLock()
	informersCopy := make(map[string]cache.SharedInformer)
	for k, v := range m.informers {
		informersCopy[k] = v
	}
	m.mu.RUnlock()

	// 等待所有 informer 同步
	syncedCount := 0
	for name, informer := range informersCopy {
		if cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
			items := informer.GetStore().List()
			utils.LogInfo("Informer synced", map[string]interface{}{
				"cluster":    m.clusterName,
				"reportType": name,
				"count":      len(items),
			})
			syncedCount++
		} else {
			utils.LogWarning("Informer sync timeout, will continue with partial data", map[string]interface{}{
				"cluster":    m.clusterName,
				"reportType": name,
				"timeout":    timeout.String(),
			})
		}
	}

	if syncedCount == 0 {
		utils.LogWarning("No informers synced, watch updates may not work", map[string]interface{}{
			"cluster": m.clusterName,
		})
		return
	}

	// 等待一段时间确保数据稳定
	select {
	case <-time.After(2 * time.Second):
	case <-m.ctx.Done():
		return
	}

	// 加载现有资源到缓存
	for _, reportType := range reports {
		m.mu.RLock()
		informer, ok := m.informers[reportType.Name]
		m.mu.RUnlock()
		if !ok {
			continue
		}
		items := informer.GetStore().List()
		utils.LogInfo("Loading existing resources from informer cache", map[string]interface{}{
			"cluster":    m.clusterName,
			"reportType": reportType.Name,
			"count":      len(items),
		})
		for _, item := range items {
			m.onAdd(reportType, item)
		}
	}

	utils.LogInfo("Informer warmup completed", map[string]interface{}{
		"cluster":     m.clusterName,
		"syncedCount": syncedCount,
		"totalCount":  len(informersCopy),
	})
}

func (m *ReportInformerManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// 先取消 context，通知所有 informer 停止
	m.cancel()
	
	// 等待一段时间让 informer 优雅关闭
	// 注意：这里在锁内等待，因为需要确保 Stop 完成后才能进行其他操作
	time.Sleep(1 * time.Second)
	
	// 清空 informers map
	m.informers = make(map[string]cache.SharedInformer)
}

func (m *ReportInformerManager) onAdd(reportType config.ReportKind, obj interface{}) {
	unstructuredObj, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return
	}
	report := m.convertToReport(reportType, unstructuredObj)
	if report != nil && m.cacheUpdater != nil {
		m.cacheUpdater.SetReport(m.clusterName, report.Namespace, report.Type, report.Name, report)
	}
}

func (m *ReportInformerManager) onUpdate(reportType config.ReportKind, oldObj, newObj interface{}) {
	unstructuredObj, ok := newObj.(*unstructured.Unstructured)
	if !ok {
		return
	}
	report := m.convertToReport(reportType, unstructuredObj)
	if report != nil && m.cacheUpdater != nil {
		m.cacheUpdater.SetReport(m.clusterName, report.Namespace, report.Type, report.Name, report)
	}
}

func (m *ReportInformerManager) onDelete(reportType config.ReportKind, obj interface{}) {
	unstructuredObj, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return
	}
	namespace := unstructuredObj.GetNamespace()
	name := unstructuredObj.GetName()
	if m.cacheUpdater != nil {
		m.cacheUpdater.DeleteReport(m.clusterName, namespace, reportType.Name, name)
	}
}

func (m *ReportInformerManager) convertToReport(reportType config.ReportKind, obj *unstructured.Unstructured) *Report {
	status := m.extractStatus(obj.Object)
	return &Report{
		Type:      reportType.Name,
		Cluster:   m.clusterName,
		Namespace: obj.GetNamespace(),
		Name:      obj.GetName(),
		Status:    status,
		Data:      obj.Object,
	}
}

func (m *ReportInformerManager) extractStatus(obj map[string]interface{}) string {
	status := "Unknown"
	if reportObj, ok := obj["report"].(map[string]interface{}); ok {
		if summaryData, ok := reportObj["summary"].(map[string]interface{}); ok {
			if criticalCount, ok := summaryData["criticalCount"].(float64); ok && criticalCount > 0 {
				status = "Critical"
			} else if highCount, ok := summaryData["highCount"].(float64); ok && highCount > 0 {
				status = "High"
			} else if mediumCount, ok := summaryData["mediumCount"].(float64); ok && mediumCount > 0 {
				status = "Medium"
			} else if lowCount, ok := summaryData["lowCount"].(float64); ok && lowCount > 0 {
				status = "Low"
			} else if noneCount, ok := summaryData["noneCount"].(float64); ok && noneCount > 0 {
				status = "None"
			}
		}
	}
	return status
}
