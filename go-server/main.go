// Main application entry point - Trivy UI server bootstraps components and starts HTTP server
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/cors"
	"golang.org/x/term"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"trivy-ui/api"
	"trivy-ui/auth"
	"trivy-ui/config"
	"trivy-ui/dataaccess"
	_ "trivy-ui/docs"
	"trivy-ui/kubernetes"
	"trivy-ui/utils"

	httpSwagger "github.com/swaggo/http-swagger"
)

type clusterInfo struct {
	Name       string
	Kubeconfig string
	InCluster  bool
	// Context selects the kubeconfig context to use. Empty means current-context.
	Context string
}

func sourceFingerprint(source clusterInfo, client *kubernetes.Client) string {
	hash := sha256.New()
	config := client.Config()
	if config != nil {
		sourceType := "kubeconfig"
		if source.InCluster {
			sourceType = "inCluster"
		}
		host := strings.TrimRight(strings.TrimSpace(config.Host), "/")
		_, _ = fmt.Fprintf(hash, "%s\x00%s\x00%s\x00%s\x00", source.Name, sourceType, host, config.ServerName)
		hash.Write(config.CAData)
		if config.CAFile != "" {
			if data, err := os.ReadFile(config.CAFile); err == nil {
				hash.Write(data)
			}
		}
	}
	return hex.EncodeToString(hash.Sum(nil))
}

type clusterSourceConfig struct {
	Type string `json:"type"`
	Key  string `json:"key,omitempty"`
}

type corsSettings struct {
	allowedOrigins   []string
	allowCredentials bool
}

func corsSettingsFromEnv() corsSettings {
	settings := corsSettings{allowedOrigins: []string{"*"}}
	rawOrigins := strings.TrimSpace(os.Getenv("CORS_ALLOWED_ORIGINS"))
	if rawOrigins == "" {
		return settings
	}
	settings.allowedOrigins = nil
	for _, origin := range strings.Split(rawOrigins, ",") {
		if trimmed := strings.TrimSpace(origin); trimmed != "" {
			settings.allowedOrigins = append(settings.allowedOrigins, trimmed)
		}
	}
	if len(settings.allowedOrigins) == 0 {
		settings.allowedOrigins = []string{"*"}
		return settings
	}
	settings.allowCredentials = !(len(settings.allowedOrigins) == 1 && settings.allowedOrigins[0] == "*")
	return settings
}

func applyCORSCookiePolicy(cfg *auth.Config, settings corsSettings, sameSiteExplicit bool) {
	if settings.allowCredentials && !sameSiteExplicit {
		cfg.CookieSameSite = "none"
	}
}

func validClusterAlias(alias string) bool {
	if alias == "" || len(alias) > 63 {
		return false
	}
	for _, r := range alias {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

// legacyDisplayName maps a kubeconfig context name to the cluster alias used by
// legacy auto-discovery (i.e. when CLUSTER_SOURCES is not configured). ARN-style
// EKS context names are shortened to their cluster name segment.
func legacyDisplayName(contextName string) string {
	if strings.HasPrefix(contextName, "arn:aws:eks:") && strings.Contains(contextName, ":cluster/") {
		parts := strings.Split(contextName, ":cluster/")
		if len(parts) == 2 {
			return parts[1]
		}
	}
	return contextName
}

func loadConfiguredClusters(dir string) ([]clusterInfo, error) {
	raw := strings.TrimSpace(os.Getenv("CLUSTER_SOURCES"))
	if raw == "" {
		return nil, nil
	}

	var sources map[string]clusterSourceConfig
	if err := json.Unmarshal([]byte(raw), &sources); err != nil {
		return nil, fmt.Errorf("parse CLUSTER_SOURCES: %w", err)
	}
	aliases := make([]string, 0, len(sources))
	for alias := range sources {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)

	clusters := make([]clusterInfo, 0, len(aliases))
	for _, alias := range aliases {
		source := sources[alias]
		if !validClusterAlias(alias) {
			return nil, fmt.Errorf("invalid cluster alias %q", alias)
		}
		switch source.Type {
		case "inCluster":
			clusters = append(clusters, clusterInfo{Name: alias, InCluster: true})
		case "kubeconfig":
			if source.Key == "" {
				return nil, fmt.Errorf("cluster %q requires a kubeconfig key", alias)
			}
			if filepath.Base(source.Key) != source.Key {
				return nil, fmt.Errorf("cluster %q kubeconfig key must name a file in the mounted Secret", alias)
			}
			path := filepath.Join(dir, source.Key)
			if _, err := os.Stat(path); err != nil {
				return nil, fmt.Errorf("cluster %q kubeconfig %q is not available: %w", alias, source.Key, err)
			}
			clusters = append(clusters, clusterInfo{Name: alias, Kubeconfig: path})
		default:
			return nil, fmt.Errorf("cluster %q has unsupported source type %q", alias, source.Type)
		}
	}
	return clusters, nil
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "hash-password" {
		runHashPassword(os.Args[2:])
		return
	}
	cfg := config.Get()
	corsSettings := corsSettingsFromEnv()
	authConfig, err := auth.ConfigFromEnv()
	if err != nil {
		utils.LogError("Failed to parse authentication configuration", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}
	applyCORSCookiePolicy(&authConfig, corsSettings, os.Getenv("AUTH_COOKIE_SAME_SITE") != "")
	authService, err := auth.NewService(authConfig)
	if err != nil {
		utils.LogError("Failed to initialize authentication", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}
	sourceScope, err := dataaccess.NewFromEnv()
	if err != nil {
		utils.LogError("Failed to initialize cluster source scope", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}
	if err := api.ValidateTrustedProxyCIDRs(os.Getenv("TRUSTED_PROXY_CIDRS")); err != nil {
		utils.LogError("Failed to initialize trusted proxy configuration", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}
	if err := api.LoadErrorPageConfigFromEnv(); err != nil {
		utils.LogError("Failed to initialize custom error page configuration", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}
	utils.LogInfo("Server starting", map[string]interface{}{
		"version":   GetVersion(),
		"host":      cfg.Host,
		"port":      cfg.Port,
		"data_path": cfg.DataPath,
		"log_level": os.Getenv("LOG_LEVEL"),
	})

	if err := api.LoadCache(); err != nil {
		utils.LogWarning("Failed to load cache", map[string]interface{}{"error": err.Error()})
	}

	cacheSvc := api.NewCacheServiceImpl()
	clusterRegistry := api.InitDefaultRegistry(cacheSvc)

	hasCache := api.HasCacheData()
	if hasCache {
		utils.LogInfo("Cache data found, K8s init will run in background")
	} else {
		utils.LogInfo("No cache found, initializing Kubernetes clients synchronously")
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

	var clustersToInit []clusterInfo
	configuredClusters, err := loadConfiguredClusters(kubeconfigDir)
	if err != nil {
		utils.LogError("Failed to load explicit cluster sources", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}

	if configuredClusters != nil {
		clustersToInit = configuredClusters
	} else {

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
					// Legacy auto-discovery: initialize every reachable context in the file.
					contextNames := make([]string, 0, len(rawConfig.Contexts))
					for name := range rawConfig.Contexts {
						contextNames = append(contextNames, name)
					}
					sort.Strings(contextNames) // deterministic startup order per file
					for _, contextName := range contextNames {
						displayName := legacyDisplayName(contextName)
						if !validClusterAlias(displayName) {
							utils.LogWarning("Skipping kubeconfig context with invalid legacy cluster alias", map[string]interface{}{"file": file.Name(), "cluster": displayName})
							continue
						}
						clustersToInit = append(clustersToInit, clusterInfo{Name: displayName, Kubeconfig: path, Context: contextName})
					}
				}
			}
		}
		if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
			clustersToInit = append(clustersToInit, clusterInfo{Name: "incluster", InCluster: true})
		}
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			home := os.Getenv("HOME")
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
		if _, err := os.Stat(kubeconfig); err == nil {
			if rawConfig, err := clientcmd.LoadFromFile(kubeconfig); err == nil {
				// Legacy auto-discovery: initialize every reachable context in the file.
				contextNames := make([]string, 0, len(rawConfig.Contexts))
				for name := range rawConfig.Contexts {
					contextNames = append(contextNames, name)
				}
				sort.Strings(contextNames) // deterministic first-cluster + stable startup order
				for _, contextName := range contextNames {
					displayName := legacyDisplayName(contextName)
					if !validClusterAlias(displayName) {
						utils.LogWarning("Skipping kubeconfig context with invalid legacy cluster alias", map[string]interface{}{"cluster": displayName})
						continue
					}
					clustersToInit = append(clustersToInit, clusterInfo{Name: displayName, Kubeconfig: kubeconfig, Context: contextName})
				}
			}
		}
	}
	seenClusters := make(map[string]struct{}, len(clustersToInit))
	uniqueClusters := clustersToInit[:0]
	for _, cluster := range clustersToInit {
		if _, exists := seenClusters[cluster.Name]; exists {
			if configuredClusters != nil {
				// Explicit CLUSTER_SOURCES config: duplicates are a configuration error.
				utils.LogError("Duplicate cluster alias", map[string]interface{}{"cluster": cluster.Name})
				os.Exit(1)
			}
			// Legacy auto-discovery: ARN short-names may collide across contexts/accounts.
			// First context (sorted, deterministic) wins; skip the rest instead of crashing.
			utils.LogWarning("Duplicate cluster alias from kubeconfig auto-discovery, skipping", map[string]interface{}{"cluster": cluster.Name})
			continue
		}
		seenClusters[cluster.Name] = struct{}{}
		uniqueClusters = append(uniqueClusters, cluster)
	}
	clustersToInit = uniqueClusters
	activeAliases := make([]string, 0, len(clustersToInit))
	for _, cluster := range clustersToInit {
		activeAliases = append(activeAliases, cluster.Name)
	}
	sourceScope.SetInitializedClusters(activeAliases)
	api.PruneClusterCache(activeAliases)

	newKubernetesClient := func(cluster clusterInfo) (*kubernetes.Client, error) {
		clientConfig := kubernetes.DefaultClientConfig()
		clientConfig.UseInCluster = cluster.InCluster
		clientConfig.Context = cluster.Context
		return kubernetes.NewClientWithConfig(cluster.Kubeconfig, clientConfig)
	}

	monitorCRDs := func(clusterName string, k8sClient *kubernetes.Client, registry *config.CRDRegistry) {
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				previousRefresh := registry.GetLastRefreshTime()
				if err := registry.RefreshIfNeeded(k8sClient.Config()); err != nil {
					utils.LogWarning("Failed to refresh Trivy Operator CRDs", map[string]interface{}{"cluster": clusterName, "error": err.Error()})
					continue
				}
				if !registry.GetLastRefreshTime().After(previousRefresh) {
					continue
				}
				if err := k8sClient.RefreshInformer(); err != nil {
					utils.LogWarning("Failed to refresh report informers", map[string]interface{}{"cluster": clusterName, "error": err.Error()})
				}
			}
		}()
	}

	initCluster := func(c clusterInfo) *kubernetes.Client {
		k8sClient, err := newKubernetesClient(c)
		if err != nil {
			utils.LogWarning("Failed to create Kubernetes client", map[string]interface{}{"cluster": c.Name, "error": err.Error()})
			return nil
		}

		reportRegistry := config.NewCRDRegistry()
		if err := clusterRegistry.Register(c.Name, k8sClient, reportRegistry); err != nil {
			utils.LogWarning("Failed to set cluster client", map[string]interface{}{"cluster": c.Name, "error": err.Error()})
		}
		api.SetClusterFingerprint(c.Name, sourceFingerprint(c, k8sClient))

		cacheUpdater := api.NewCacheUpdater(clusterRegistry)
		startInformer := func() {
			if err := k8sClient.StartInformerWithRegistry(c.Name, cacheUpdater, reportRegistry); err != nil {
				utils.LogWarning("Failed to start informer", map[string]interface{}{"cluster": c.Name, "error": err.Error(), "message": "Reports will still be available but won't auto-update via watch"})
			} else {
				utils.LogInfo("Started informer for cluster", map[string]interface{}{"cluster": c.Name, "message": "Reports will auto-update on changes"})
			}
		}
		monitorCRDs(c.Name, k8sClient, reportRegistry)
		if err := reportRegistry.DiscoverCRDs(k8sClient.Config()); err != nil {
			utils.LogWarning("Failed to discover Cluster report types", map[string]interface{}{"cluster": c.Name, "error": err.Error()})
			go func() {
				for attempt := 1; attempt <= 10; attempt++ {
					delay := time.Duration(1<<(attempt-1)) * time.Second
					if delay > time.Minute {
						delay = time.Minute
					}
					time.Sleep(delay)
					if err := reportRegistry.DiscoverCRDs(k8sClient.Config()); err == nil {
						startInformer()
						return
					}
				}
				utils.LogError("Failed to discover Cluster report types after retries", map[string]interface{}{"cluster": c.Name})
			}()
		} else {
			startInformer()
		}
		return k8sClient
	}

	initK8s := func() {
		registry := config.GetGlobalRegistry()

		if len(clustersToInit) == 0 {
			return
		}

		first := clustersToInit[0]
		firstClient, err := newKubernetesClient(first)
		if err != nil {
			utils.LogWarning("Failed to create Kubernetes client", map[string]interface{}{"cluster": first.Name, "error": err.Error()})
		} else {
			clients[first.Name] = firstClient
			if err := clusterRegistry.Register(first.Name, firstClient, registry); err != nil {
				utils.LogWarning("Failed to set cluster client", map[string]interface{}{"cluster": first.Name, "error": err.Error()})
			}
			api.SetClusterFingerprint(first.Name, sourceFingerprint(first, firstClient))
			cacheUpdater := api.NewCacheUpdater(clusterRegistry)
			startInformer := func() {
				if err := firstClient.StartInformerWithRegistry(first.Name, cacheUpdater, registry); err != nil {
					utils.LogWarning("Failed to start informer", map[string]interface{}{"cluster": first.Name, "error": err.Error(), "message": "Reports will still be available but won't auto-update via watch"})
				} else {
					utils.LogInfo("Started informer for cluster", map[string]interface{}{"cluster": first.Name, "message": "Reports will auto-update on changes"})
				}
			}
			monitorCRDs(first.Name, firstClient, registry)
			restConfig := firstClient.Config()
			if restConfig != nil {
				utils.LogInfo("Discovering Trivy Operator CRDs")
				if err := registry.DiscoverCRDs(restConfig); err != nil {
					utils.LogWarning("Failed to discover CRDs", map[string]interface{}{
						"cluster": first.Name,
						"error":   err.Error(),
						"message": "Will retry in background. Make sure Trivy Operator is installed.",
					})
					go func(cfg *rest.Config) {
						for attempt := 1; attempt <= 10; attempt++ {
							delay := time.Duration(1<<(attempt-1)) * time.Second
							if delay > time.Minute {
								delay = time.Minute
							}
							time.Sleep(delay)
							utils.LogDebug("Retrying CRD discovery", map[string]interface{}{"cluster": first.Name, "attempt": attempt})
							if err := registry.DiscoverCRDs(cfg); err == nil {
								reports := registry.GetAllReports()
								utils.LogInfo("Successfully discovered CRDs on retry", map[string]interface{}{
									"cluster": first.Name,
									"attempt": attempt,
									"count":   len(reports),
								})
								startInformer()
								return
							}
						}
						utils.LogError("Failed to discover CRDs after retries", map[string]interface{}{"cluster": first.Name})
					}(restConfig)
				} else {
					reports := registry.GetAllReports()
					utils.LogInfo("Discovered Trivy Operator CRD types", map[string]interface{}{"cluster": first.Name, "count": len(reports)})
					for _, r := range reports {
						scope := "Namespaced"
						if !r.Namespaced {
							scope = "Cluster"
						}
						utils.LogDebug("CRD type discovered", map[string]interface{}{"cluster": first.Name, "name": r.Name, "kind": r.Kind, "scope": scope})
					}
					startInformer()
				}
			}
		}

		if len(clustersToInit) > 1 {
			var wg sync.WaitGroup
			var mu sync.Mutex
			for _, c := range clustersToInit[1:] {
				wg.Add(1)
				go func(cc clusterInfo) {
					defer wg.Done()
					if k8sClient := initCluster(cc); k8sClient != nil {
						mu.Lock()
						clients[cc.Name] = k8sClient
						mu.Unlock()
					}
				}(c)
			}
			wg.Wait()
		}
		initializedClusters := make([]string, 0, len(clients))
		for cluster := range clients {
			initializedClusters = append(initializedClusters, cluster)
		}
		sourceScope.SetInitializedClusters(initializedClusters)

		api.SetWarmupCompleted()

		if hasCache {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
				defer cancel()
				api.ValidateAndCleanupCache(ctx)
			}()
		}
	}

	// Check for static files in different locations (do this before initK8s to avoid delay)
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
	if hasCache {
		// When cache exists, start K8s initialization in background
		// Server can serve cached data immediately with nil client
		go initK8s()
		utils.LogInfo("Starting with cached data, K8s clients initializing in background")
	} else {
		// No cache - must initialize K8s synchronously to have a working client
		initK8s()
		for _, c := range clustersToInit {
			if client, ok := clients[c.Name]; ok {
				firstClient = client
				break
			}
		}
		if firstClient == nil {
			utils.LogError("No Kubernetes client initialized, exiting", nil)
			os.Exit(1)
		}
	}
	router := api.NewRouter(firstClient, staticPath, cacheSvc, clusterRegistry, config.GetGlobalRegistry(), authService, sourceScope)
	utils.LogInfo("Router created")

	corsHandler := cors.New(cors.Options{
		AllowedOrigins: corsSettings.allowedOrigins,
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
		AllowCredentials:   corsSettings.allowCredentials,
		MaxAge:             300,
		OptionsPassthrough: false,
		Debug:              false,
	})
	utils.LogInfo("CORS handler created")

	http.Handle("/swagger/", http.StripPrefix("/swagger/", httpSwagger.WrapHandler))

	accessLogHandler := corsHandler.Handler(router)
	httpHandler := api.CompressHandler(accessLogHandler)

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	utils.LogInfo("Listening", map[string]interface{}{"address": addr})
	server := &http.Server{
		Addr:              addr,
		Handler:           httpHandler,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
	}
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.ListenAndServe()
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-serverErr:
		if err != nil && err != http.ErrServerClosed {
			utils.LogError("Server failed to start", map[string]interface{}{"error": err.Error()})
			os.Exit(1)
		}
	case sig := <-shutdown:
		utils.LogInfo("Shutting down server", map[string]interface{}{"signal": sig.String()})
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			utils.LogError("Server shutdown failed", map[string]interface{}{"error": err.Error()})
		}
	}
}

func runHashPassword(args []string) {
	password := ""
	if len(args) > 0 {
		password = args[0]
	} else {
		fmt.Print("Password: ")
		if term.IsTerminal(int(os.Stdin.Fd())) {
			value, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			password = string(value)
		} else {
			line, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if err != nil && len(line) == 0 {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			password = strings.TrimRight(line, "\r\n")
		}
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(hash)
}
