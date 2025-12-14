package api

import (
	"context"
	"time"

	"trivy-ui/config"
	"trivy-ui/utils"
)

func Warmup(ctx context.Context) {
	utils.LogInfo("Starting warmup")
	registry := config.GetGlobalRegistry()
	reports := registry.GetAllReports()

	if len(reports) == 0 {
		utils.LogWarning("No report types discovered for warmup", nil)
		return
	}

	clients := GetAllClusterClients()
	if len(clients) == 0 {
		utils.LogWarning("No cluster clients available for warmup", nil)
		return
	}

	utils.LogInfo("Warming up all report types", map[string]interface{}{
		"report_types":  len(reports),
		"cluster_count": len(clients),
	})

	// 为每个报告类型启动预热
	for _, reportType := range reports {
		go warmupReportType(ctx, reportType, clients)
	}

	utils.LogInfo("Warmup initiated for all report types")
}

// warmupReportType 预热单个报告类型
func warmupReportType(ctx context.Context, reportType config.ReportKind, clients map[string]*ClusterClient) {
	utils.LogInfo("Warming up report type", map[string]interface{}{
		"type":       reportType.Name,
		"namespaced": reportType.Namespaced,
	})

	totalReports := 0
	for clusterName, clusterClient := range clients {
		func(name string, cc *ClusterClient) {
			ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
			defer cancel()

			var reports []Report

			if reportType.Namespaced {
				// 命名空间级别的报告
				for _, ns := range cc.Namespaces {
					nsReports, nsErr := cc.Client.GetReportsByType(ctx, reportType, ns)
					if nsErr != nil {
						utils.LogDebug("Failed to get reports for namespace", map[string]interface{}{
							"cluster":   name,
							"namespace": ns,
							"type":      reportType.Name,
							"error":     nsErr.Error(),
						})
						continue
					}
					for _, rep := range nsReports {
						apiReport := Report{
							Type:      rep.Type,
							Cluster:   name,
							Namespace: rep.Namespace,
							Name:      rep.Name,
							Status:    rep.Status,
							Data:      rep.Data,
							UpdatedAt: time.Now(),
						}
						UpsertReportToCache(apiReport)
						reports = append(reports, apiReport)
					}
				}
			} else {
				// 集群级别的报告
				clusterReports, clusterErr := cc.Client.GetReportsByType(ctx, reportType, "")
				if clusterErr != nil {
					utils.LogDebug("Failed to get cluster-scoped reports", map[string]interface{}{
						"cluster": name,
						"type":    reportType.Name,
						"error":   clusterErr.Error(),
					})
				} else {
					for _, rep := range clusterReports {
						apiReport := Report{
							Type:      rep.Type,
							Cluster:   name,
							Namespace: rep.Namespace,
							Name:      rep.Name,
							Status:    rep.Status,
							Data:      rep.Data,
							UpdatedAt: time.Now(),
						}
						UpsertReportToCache(apiReport)
						reports = append(reports, apiReport)
					}
				}
			}

			totalReports += len(reports)
			utils.LogInfo("Warmed up report type for cluster", map[string]interface{}{
				"cluster": name,
				"type":    reportType.Name,
				"count":   len(reports),
			})
		}(clusterName, clusterClient)
	}

	utils.LogInfo("Completed warmup for report type", map[string]interface{}{
		"type":  reportType.Name,
		"total": totalReports,
	})
}

