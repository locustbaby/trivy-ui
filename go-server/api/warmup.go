package api

import (
	"context"
	"sync"
	"time"

	"trivy-ui/config"
	"trivy-ui/utils"
)

func Warmup(ctx context.Context) {
	utils.LogInfo("Starting warmup")
	registry := config.GetGlobalRegistry()
	reports := registry.GetAllReports()

	var vulnerabilityReportType *config.ReportKind
	for _, r := range reports {
		if r.Name == "vulnerabilityreports" {
			vulnerabilityReportType = &r
			break
		}
	}

	clients := GetAllClusterClients()

	if vulnerabilityReportType != nil {
		utils.LogInfo("Warming up vulnerabilityreports", map[string]interface{}{"cluster_count": len(clients)})
		
		var wg sync.WaitGroup
		for clusterName, clusterClient := range clients {
			wg.Add(1)
			go func(name string, cc *ClusterClient) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()

				if vulnerabilityReportType.Namespaced {
					for _, ns := range cc.Namespaces {
						reports, err := cc.Client.GetReportsByType(ctx, *vulnerabilityReportType, ns)
						if err == nil {
							for _, rep := range reports {
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
							}
						}
					}
				} else {
					reports, err := cc.Client.GetReportsByType(ctx, *vulnerabilityReportType, "")
					if err == nil {
						for _, rep := range reports {
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
						}
					}
				}
				utils.LogInfo("Warmed up vulnerabilityreports for cluster", map[string]interface{}{"cluster": name})
			}(clusterName, clusterClient)
		}
		wg.Wait()
	}

	utils.LogInfo("Warmup completed")
}
