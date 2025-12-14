// Main application entry point - Trivy UI server bootstraps components and starts HTTP server
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/cors"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"trivy-ui/api"
	"trivy-ui/config"
	_ "trivy-ui/docs"
	"trivy-ui/kubernetes"
	"trivy-ui/utils"

	httpSwagger "github.com/swaggo/http-swagger"
)

func main() {
	utils.LogInfo("Server starting", map[string]interface{}{"version": GetVersion()})
	utils.LogInfo("Configuration loaded")
	cfg := config.Get()

	if err := api.LoadCache(); err != nil {
		utils.LogWarning("Failed to load cache", map[string]interface{}{"error": err.Error()})
	}

	// 多集群 client map
	clients := make(map[string]*kubernetes.Client)

	// 支持通过目录批量加载 kubeconfig
	kubeconfigDir := os.Getenv("KUBECONFIG_DIR")
	if kubeconfigDir == "" {
		kubeconfigDir = os.Getenv("KUBECONFIGDIR") // 兼容另一种写法
	}
	if kubeconfigDir == "" {
		kubeconfigDir = os.Getenv("KUBE_CONFIG_DIR") // 兼容另一种写法
	}
	if kubeconfigDir == "" {
		kubeconfigDir = "/kubeconfigs"
	}

	var clustersToInit []struct {
		Name       string
		Kubeconfig string
	}

	if kubeconfigDir != "" {
		if stat, err := os.Stat(kubeconfigDir); err == nil && stat.IsDir() {
			files, err := os.ReadDir(kubeconfigDir)
			if err != nil {
				utils.LogError("Failed to read kubeconfig dir", map[string]interface{}{"error": err.Error()})
			}
			for _, file := range files {
				if file.IsDir() {
					continue
				}
				if strings.HasPrefix(file.Name(), ".") {
					continue
				}
				path := filepath.Join(kubeconfigDir, file.Name())
				rawConfig, err := clientcmd.LoadFromFile(path)
				if err != nil {
					utils.LogInfo("Skipping kubeconfig file", map[string]interface{}{"file": file.Name(), "error": err.Error()})
					continue
				}
				clusterName := ""
				for name := range rawConfig.Clusters {
					clusterName = name
					break
				}
				if clusterName == "" {
					utils.LogInfo("No cluster found in kubeconfig file", map[string]interface{}{"file": file.Name()})
					continue
				}
				if strings.Contains(clusterName, "/") {
					parts := strings.Split(clusterName, "/")
					clusterName = parts[len(parts)-1]
				} else if strings.Contains(clusterName, ":") {
					parts := strings.Split(clusterName, ":")
					clusterName = parts[len(parts)-1]
				}
				k8sClient, err := kubernetes.NewClient(path)
				if err != nil {
					utils.LogInfo("Skipping kubeconfig file", map[string]interface{}{"file": file.Name(), "error": err.Error()})
					continue
				}
				clustersToInit = append(clustersToInit, struct{ Name, Kubeconfig string }{clusterName, path})
				clients[clusterName] = k8sClient
			}
		}
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		clustersToInit = append(clustersToInit, struct{ Name, Kubeconfig string }{"incluster", ""})
	}
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home := os.Getenv("HOME")
		kubeconfig = filepath.Join(home, ".kube", "config")
	}
	if _, err := os.Stat(kubeconfig); err == nil {
		if rawConfig, err := clientcmd.LoadFromFile(kubeconfig); err == nil {
			contextName := rawConfig.CurrentContext
			if contextName != "" {
				if strings.HasPrefix(contextName, "arn:aws:eks:") && strings.Contains(contextName, ":cluster/") {
					parts := strings.Split(contextName, ":cluster/")
					if len(parts) == 2 {
						contextName = parts[1]
					}
				}
				clustersToInit = append(clustersToInit, struct{ Name, Kubeconfig string }{contextName, kubeconfig})
			}
		}
	}

	registry := config.GetGlobalRegistry()
	var firstRestConfig *rest.Config

	for _, c := range clustersToInit {
		k8sClient, err := kubernetes.NewClient(c.Kubeconfig)
		if err != nil {
			utils.LogWarning("Failed to create Kubernetes client", map[string]interface{}{"cluster": c.Name, "error": err.Error()})
			continue
		}
		clients[c.Name] = k8sClient

		restConfig, _ := clientcmd.BuildConfigFromFlags("", c.Kubeconfig)
		if firstRestConfig == nil && restConfig != nil {
			firstRestConfig = restConfig
			utils.LogInfo("Discovering Trivy Operator CRDs")
			if err := registry.DiscoverCRDs(restConfig); err != nil {
				utils.LogWarning("Failed to discover CRDs", map[string]interface{}{"error": err.Error(), "message": "Will retry on next request. Make sure Trivy Operator is installed."})
			} else {
				reports := registry.GetAllReports()
				utils.LogInfo("Discovered Trivy Operator CRD types", map[string]interface{}{"count": len(reports)})
				for _, r := range reports {
					scope := "Namespaced"
					if !r.Namespaced {
						scope = "Cluster"
					}
					utils.LogDebug("CRD type discovered", map[string]interface{}{"name": r.Name, "kind": r.Kind, "scope": scope})
				}
			}
		}

		if err := api.SetClusterClient(c.Name, k8sClient); err != nil {
			utils.LogWarning("Failed to set cluster client", map[string]interface{}{"cluster": c.Name, "error": err.Error()})
		}

		cacheUpdater := api.NewCacheUpdater()
		if err := k8sClient.StartInformer(c.Name, cacheUpdater); err != nil {
			utils.LogWarning("Failed to start informer", map[string]interface{}{"cluster": c.Name, "error": err.Error(), "message": "Reports will still be available but won't auto-update via watch"})
		} else {
			utils.LogInfo("Started informer for cluster", map[string]interface{}{"cluster": c.Name, "message": "Reports will auto-update on changes"})
		}
	}

	go api.Warmup(context.Background())

	// Check for static files in different locations
	staticPath := os.Getenv("STATIC_PATH")
	if staticPath == "" {
		possiblePaths := []string{
			"trivy-dashboard/dist",
			"../trivy-dashboard/dist",
			"/app/trivy-dashboard/dist",
			"web/dist",
		}
		for _, path := range possiblePaths {
			if _, err := os.Stat(path); err == nil {
				staticPath = path
				break
			}
		}
		if staticPath == "" {
			staticPath = "trivy-dashboard/dist"
			utils.LogWarning("Static files not found, using default path", map[string]interface{}{"path": staticPath})
		}
	}
	indexPath := filepath.Join(staticPath, "index.html")
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		utils.LogWarning("index.html not found", map[string]interface{}{"path": indexPath})
	} else {
		utils.LogInfo("Found index.html", map[string]interface{}{"path": indexPath})
	}
	utils.LogInfo("Using static files", map[string]interface{}{"path": staticPath})

	var firstClient *kubernetes.Client
	for _, c := range clustersToInit {
		if client, ok := clients[c.Name]; ok {
			firstClient = client
			break
		}
	}
	if firstClient == nil {
		utils.LogError("No Kubernetes client initialized", nil)
		log.Fatalf("No Kubernetes client initialized!")
	}
	router := api.NewRouter(firstClient, staticPath)
	utils.LogInfo("Router created")

	corsHandler := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodDelete,
			http.MethodOptions,
			http.MethodHead,
		},
		AllowedHeaders: []string{
			"Accept",
			"Authorization",
			"Content-Type",
			"X-CSRF-Token",
			"Cache-Control",
		},
		ExposedHeaders:     []string{"Link"},
		AllowCredentials:   false,
		MaxAge:             300,
		OptionsPassthrough: false,
		Debug:              false,
	})
	utils.LogInfo("CORS handler created")

	http.Handle("/swagger/", http.StripPrefix("/swagger/", httpSwagger.WrapHandler))

	accessLogHandler := api.AccessLogHandler(corsHandler.Handler(router))

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	utils.LogInfo("Server starting", map[string]interface{}{"address": addr})
	if err := http.ListenAndServe(addr, accessLogHandler); err != nil {
		utils.LogError("Server failed to start", map[string]interface{}{"error": err.Error()})
		log.Fatalf("Server failed to start: %v", err)
	}
}
