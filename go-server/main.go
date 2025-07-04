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
	"k8s.io/client-go/tools/clientcmd"

	"trivy-ui/api"
	"trivy-ui/config"
	_ "trivy-ui/docs" // swaggo 文档自动注册
	"trivy-ui/kubernetes"

	httpSwagger "github.com/swaggo/http-swagger"
)

func main() {
	// Display version information
	fmt.Printf("Trivy UI Server v%s\n", GetVersion())

	// Load configuration
	fmt.Println("Configuration loaded")
	cfg := config.Get()

	// 启动时加载本地缓存
	api.LoadCache()

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
	if kubeconfigDir != "" {
		if _, err := os.ReadDir(kubeconfigDir); err != nil {
			fmt.Printf("Info: kubeconfig dir %s not found, fallback to single kubeconfig/incluster mode\n", kubeconfigDir)
			kubeconfigDir = ""
		}
	}

	var clustersToInit []struct {
		Name       string
		Kubeconfig string
	}

	if kubeconfigDir != "" {
		files, _ := os.ReadDir(kubeconfigDir)
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
				fmt.Printf("Info: Skipping %s: %v\n", file.Name(), err)
				continue
			}
			clusterName := ""
			for name := range rawConfig.Clusters {
				clusterName = name
				break // 只取第一个
			}
			if clusterName == "" {
				fmt.Printf("Info: No cluster found in %s\n", file.Name())
				continue
			}
			k8sClient, err := kubernetes.NewClient(path)
			if err != nil {
				fmt.Printf("Info: Skipping %s: %v\n", file.Name(), err)
				continue
			}
			clustersToInit = append(clustersToInit, struct{ Name, Kubeconfig string }{clusterName, path})
			clients[clusterName] = k8sClient
		}
	} else {
		// 兼容原有单 kubeconfig 逻辑
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
				clusterName := ""
				for name := range rawConfig.Clusters {
					clusterName = name
					break
				}
				if clusterName != "" {
					clustersToInit = append(clustersToInit, struct{ Name, Kubeconfig string }{clusterName, kubeconfig})
				}
			}
		}
	}

	for _, c := range clustersToInit {
		k8sClient, err := kubernetes.NewClient(c.Kubeconfig)
		if err != nil {
			fmt.Printf("Warning: Failed to create Kubernetes client for %s: %v\n", c.Name, err)
			continue
		}
		clients[c.Name] = k8sClient
		// 获取 API Server 地址和 Kubernetes 版本（类似 kubectl cluster-info）
		restConfig, _ := clientcmd.BuildConfigFromFlags("", c.Kubeconfig)
		apiServerURL := ""
		if restConfig != nil {
			apiServerURL = restConfig.Host
		}
		version := ""
		if versionInfo, err := k8sClient.Clientset().Discovery().ServerVersion(); err == nil {
			version = versionInfo.GitVersion
		}
		clusterInfo := api.Cluster{
			Name:        c.Name,
			Description: fmt.Sprintf("API Server: %s, version: %s", apiServerURL, version),
		}
		api.UpsertClusterToCache(clusterInfo)
		// 获取所有 ns
		nsList, err := k8sClient.GetNamespaces(context.Background())
		if err == nil {
			for _, ns := range nsList {
				nsObj := api.Namespace{Cluster: c.Name, Name: ns}
				api.UpsertNamespaceToCache(nsObj)
			}
		}
	}

	// 赋值给全局 clients map
	api.Clients = clients

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
			fmt.Printf("Warning: Static files not found, using default path: %s\n", staticPath)
		}
	}
	indexPath := filepath.Join(staticPath, "index.html")
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		fmt.Printf("Warning: index.html not found at %s\n", indexPath)
	} else {
		fmt.Printf("Found index.html at %s\n", indexPath)
	}
	fmt.Printf("Using static files from: %s\n", staticPath)

	// 只用第一个 client 启动 API 路由（如需多集群切换可扩展）
	var firstClient *kubernetes.Client
	for _, c := range clustersToInit {
		if client, ok := clients[c.Name]; ok {
			firstClient = client
			break
		}
	}
	if firstClient == nil {
		log.Fatalf("No Kubernetes client initialized!")
	}
	router := api.NewRouter(firstClient, staticPath)
	fmt.Println("Router created")

	// Setup CORS
	corsHandler := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodDelete,
			http.MethodOptions,
		},
		AllowedHeaders: []string{
			"Accept",
			"Authorization",
			"Content-Type",
			"X-CSRF-Token",
		},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	})
	fmt.Println("CORS handler created")

	// 注册 swagger 文档路由
	http.Handle("/swagger/", http.StripPrefix("/swagger/", httpSwagger.WrapHandler))

	// Start server
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	fmt.Printf("Server starting on %s\n", addr)
	if err := http.ListenAndServe(addr, corsHandler.Handler(router)); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
