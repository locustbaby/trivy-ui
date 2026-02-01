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
	IncrementCount(cluster, namespace, reportType string, hasVuln bool)
	DecrementCount(cluster, namespace, reportType string, hasVuln bool)
	AdjustVulnCount(cluster, namespace, reportType string, delta int)
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

	// Use a reasonable resync period to recover from missed events
	// 10 minutes is a good balance between freshness and API load
	resyncPeriod := 10 * time.Minute

	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(
		m.client.dynamic,
		resyncPeriod,
		metav1.NamespaceAll,
		nil,
	)

	for _, reportType := range reports {
		reportType := reportType // Create local copy to avoid closure capture issue
		group, version := parseAPIVersion(reportType.APIVersion)
		gvr := schema.GroupVersionResource{
			Group:    group,
			Version:  version,
			Resource: reportType.Name,
		}

		informer := factory.ForResource(gvr).Informer()

		// Add event handlers with error recovery logging
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

		// Set error handler to log watch errors (helps debug stream errors)
		informer.SetWatchErrorHandler(func(r *cache.Reflector, err error) {
			utils.LogWarning("Informer watch error, will retry", map[string]interface{}{
				"cluster":    m.clusterName,
				"reportType": reportType.Name,
				"error":      err.Error(),
			})
		})

		m.informers[reportType.Name] = informer
	}

	factory.Start(m.ctx.Done())

	syncTimeout := 2 * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), syncTimeout)
	defer cancel()

	type syncResult struct {
		name   string
		synced bool
	}

	resultCh := make(chan syncResult, len(m.informers))

	for name, informer := range m.informers {
		go func(n string, inf cache.SharedInformer) {
			ok := cache.WaitForCacheSync(ctx.Done(), inf.HasSynced)
			if ok {
				utils.LogInfo("Informer synced", map[string]interface{}{
					"cluster":    m.clusterName,
					"reportType": n,
					"count":      len(inf.GetStore().List()),
				})
			} else {
				utils.LogWarning("Informer sync timeout, will continue in background", map[string]interface{}{
					"cluster":    m.clusterName,
					"reportType": n,
				})
			}
			resultCh <- syncResult{name: n, synced: ok}
		}(name, informer)
	}

	syncedCount := 0
	for range m.informers {
		r := <-resultCh
		if r.synced {
			syncedCount++
		}
	}

	if syncedCount == 0 {
		return fmt.Errorf("no informers synced successfully")
	}

	var loadWg sync.WaitGroup
	for _, reportType := range reports {
		informer, ok := m.informers[reportType.Name]
		if !ok || !informer.HasSynced() {
			continue
		}
		items := informer.GetStore().List()
		utils.LogInfo("Loading existing resources from informer cache", map[string]interface{}{
			"cluster":    m.clusterName,
			"reportType": reportType.Name,
			"count":      len(items),
		})
		loadWg.Add(1)
		go func(rt config.ReportKind, items []interface{}) {
			defer loadWg.Done()
			for _, item := range items {
				m.onAdd(rt, item)
			}
		}(reportType, items)
	}
	loadWg.Wait()

	utils.LogInfo("Started informers for report types", map[string]interface{}{
		"cluster": m.clusterName,
		"total":   len(m.informers),
		"synced":  syncedCount,
	})
	return nil
}

func (m *ReportInformerManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cancel()
	m.informers = make(map[string]cache.SharedInformer)
}

func (m *ReportInformerManager) GetInformer(reportType string) cache.SharedInformer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.informers[reportType]
}

func (m *ReportInformerManager) GetAllInformers() map[string]cache.SharedInformer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]cache.SharedInformer, len(m.informers))
	for k, v := range m.informers {
		result[k] = v
	}
	return result
}

func (m *ReportInformerManager) onAdd(reportType config.ReportKind, obj interface{}) {
	unstructuredObj, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return
	}
	report := m.convertToReport(reportType, unstructuredObj)
	if report != nil && m.cacheUpdater != nil {
		m.cacheUpdater.SetReport(m.clusterName, report.Namespace, report.Type, report.Name, report)
		// Update counters
		hasVuln := m.hasVulnerabilities(unstructuredObj.Object)
		m.cacheUpdater.IncrementCount(m.clusterName, report.Namespace, report.Type, hasVuln)
	}
}

func (m *ReportInformerManager) onUpdate(reportType config.ReportKind, oldObj, newObj interface{}) {
	oldUnstructured, oldOk := oldObj.(*unstructured.Unstructured)
	newUnstructured, newOk := newObj.(*unstructured.Unstructured)
	if !oldOk || !newOk {
		return
	}
	report := m.convertToReport(reportType, newUnstructured)
	if report != nil && m.cacheUpdater != nil {
		m.cacheUpdater.SetReport(m.clusterName, report.Namespace, report.Type, report.Name, report)

		// Check if vulnerability status changed and adjust counters
		oldHasVuln := m.hasVulnerabilities(oldUnstructured.Object)
		newHasVuln := m.hasVulnerabilities(newUnstructured.Object)
		if oldHasVuln != newHasVuln {
			if newHasVuln {
				// Changed from no vulnerabilities to has vulnerabilities
				m.cacheUpdater.AdjustVulnCount(m.clusterName, report.Namespace, report.Type, 1)
			} else {
				// Changed from has vulnerabilities to no vulnerabilities
				m.cacheUpdater.AdjustVulnCount(m.clusterName, report.Namespace, report.Type, -1)
			}
		}
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
		// Get vulnerability status before deleting
		hasVuln := m.hasVulnerabilities(unstructuredObj.Object)
		m.cacheUpdater.DeleteReport(m.clusterName, namespace, reportType.Name, name)
		// Update counters
		m.cacheUpdater.DecrementCount(m.clusterName, namespace, reportType.Name, hasVuln)
	}
}

func (m *ReportInformerManager) convertToReport(reportType config.ReportKind, obj *unstructured.Unstructured) *Report {
	status := m.extractStatus(obj.Object)

	// Extract only summary data for cache, not full details (vulnerabilities, components, etc.)
	// This significantly reduces memory usage and avoids stream errors for large reports like SBOM
	summaryData := m.extractSummaryData(obj.Object)

	return &Report{
		Type:      reportType.Name,
		Cluster:   m.clusterName,
		Namespace: obj.GetNamespace(),
		Name:      obj.GetName(),
		Status:    status,
		Data:      summaryData,
	}
}

// extractSummaryData extracts only the essential metadata and summary from a report
// This avoids storing large arrays like vulnerabilities, components, checks in cache
func (m *ReportInformerManager) extractSummaryData(obj map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	// Copy essential metadata
	if apiVersion, ok := obj["apiVersion"]; ok {
		result["apiVersion"] = apiVersion
	}
	if kind, ok := obj["kind"]; ok {
		result["kind"] = kind
	}
	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		// Only copy essential metadata fields
		metaCopy := make(map[string]interface{})
		for _, field := range []string{"name", "namespace", "uid", "creationTimestamp", "labels", "annotations"} {
			if v, exists := metadata[field]; exists {
				metaCopy[field] = v
			}
		}
		result["metadata"] = metaCopy
	}

	// Extract report summary without large arrays
	if reportObj, ok := obj["report"].(map[string]interface{}); ok {
		reportCopy := make(map[string]interface{})

		// Copy summary (counts)
		if summary, ok := reportObj["summary"].(map[string]interface{}); ok {
			reportCopy["summary"] = summary
		}

		// Copy artifact info
		if artifact, ok := reportObj["artifact"].(map[string]interface{}); ok {
			reportCopy["artifact"] = artifact
		}

		// Copy scanner info
		if scanner, ok := reportObj["scanner"].(map[string]interface{}); ok {
			reportCopy["scanner"] = scanner
		}

		// Copy registry info
		if registry, ok := reportObj["registry"].(map[string]interface{}); ok {
			reportCopy["registry"] = registry
		}

		// Copy updateTimestamp
		if updateTimestamp, ok := reportObj["updateTimestamp"]; ok {
			reportCopy["updateTimestamp"] = updateTimestamp
		}

		// DO NOT copy large arrays: vulnerabilities, components, checks, secrets, etc.
		// These will be fetched on-demand when user requests report details

		result["report"] = reportCopy
	}

	return result
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

// hasVulnerabilities checks if a report has any vulnerabilities based on summary counts
func (m *ReportInformerManager) hasVulnerabilities(obj map[string]interface{}) bool {
	if reportObj, ok := obj["report"].(map[string]interface{}); ok {
		if summaryData, ok := reportObj["summary"].(map[string]interface{}); ok {
			severities := []string{"criticalCount", "highCount", "mediumCount", "lowCount"}
			for _, key := range severities {
				if count, ok := summaryData[key].(float64); ok && count > 0 {
					return true
				}
			}
		}
	}
	return false
}
