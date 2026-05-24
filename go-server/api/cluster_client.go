package api

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"trivy-ui/kubernetes"
)

var (
	defaultRegistry *ClusterRegistry
	registryOnce    sync.Once
)

type ClusterClient struct {
	Name         string
	Client       *kubernetes.Client
	APIServerURL string
	Version      string
	Namespaces   []string
	SyncState    string
	mu           sync.RWMutex
}

type ClusterRegistry struct {
	mu       sync.RWMutex
	clients  map[string]*ClusterClient
	cacheSvc CacheService
}

func NewClusterRegistry(cacheSvc CacheService) *ClusterRegistry {
	return &ClusterRegistry{
		clients:  make(map[string]*ClusterClient),
		cacheSvc: cacheSvc,
	}
}

func GetDefaultRegistry() *ClusterRegistry {
	registryOnce.Do(func() {
		defaultRegistry = NewClusterRegistry(NewCacheServiceImpl())
	})
	return defaultRegistry
}

func InitDefaultRegistry(cacheSvc CacheService) *ClusterRegistry {
	registryOnce.Do(func() {
		defaultRegistry = NewClusterRegistry(cacheSvc)
	})
	return defaultRegistry
}

func GetClusterClient(clusterName string) *ClusterClient {
	return GetDefaultRegistry().Get(clusterName)
}

func GetAllClusterClients() map[string]*ClusterClient {
	return GetDefaultRegistry().All()
}

func SetClusterClient(clusterName string, client *kubernetes.Client) error {
	return GetDefaultRegistry().Set(clusterName, client)
}

func (r *ClusterRegistry) Get(clusterName string) *ClusterClient {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.clients[clusterName]
}

func (r *ClusterRegistry) All() map[string]*ClusterClient {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make(map[string]*ClusterClient)
	for k, v := range r.clients {
		result[k] = v
	}
	return result
}

func (r *ClusterRegistry) Set(clusterName string, client *kubernetes.Client) error {
	apiServerURL := ""
	if restConfig := client.Config(); restConfig != nil {
		apiServerURL = restConfig.Host
	}
	version := ""
	if versionInfo, err := client.Clientset().Discovery().ServerVersion(); err == nil {
		version = versionInfo.GitVersion
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	namespaces, err := client.GetNamespaces(ctx)
	cancel()
	
	if err != nil || len(namespaces) == 0 {
		namespaces = r.recoverNamespaces(clusterName)
	}

	r.mu.Lock()
	r.clients[clusterName] = &ClusterClient{
		Name:         clusterName,
		Client:       client,
		APIServerURL: apiServerURL,
		Version:      version,
		Namespaces:   namespaces,
	}
	r.mu.Unlock()

	clusterInfo := Cluster{
		Name:        clusterName,
		Description: fmt.Sprintf("API Server: %s, version: %s", apiServerURL, version),
	}
	if r.cacheSvc != nil {
		r.cacheSvc.Set(clusterKey(clusterName), clusterInfo, 0)
		for _, ns := range namespaces {
			nsObj := Namespace{Cluster: clusterName, Name: ns}
			r.cacheSvc.Set(namespaceKey(clusterName, ns), nsObj, 0)
		}
	}

	return nil
}

func (r *ClusterRegistry) recoverNamespaces(clusterName string) []string {
	if r.cacheSvc == nil {
		return nil
	}
	
	var namespaces []string
	namespaceSet := make(map[string]bool)
	
	items := r.cacheSvc.Items()
	for k, v := range items {
		if !strings.HasPrefix(k, "namespace:") {
			continue
		}
		
		var ns Namespace
		switch val := v.(type) {
		case Namespace:
			ns = val
		case CacheItem:
			if nsVal, ok := val.Value.(Namespace); ok {
				ns = nsVal
			} else if nsMap, ok := val.Value.(map[string]interface{}); ok {
				if cluster, ok := nsMap["cluster"].(string); ok && cluster == clusterName {
					if name, ok := nsMap["name"].(string); ok && name != "" {
						if !namespaceSet[name] {
							namespaces = append(namespaces, name)
							namespaceSet[name] = true
						}
					}
				}
				continue
			} else {
				continue
			}
		case map[string]interface{}:
			if cluster, ok := val["cluster"].(string); ok && cluster == clusterName {
				if name, ok := val["name"].(string); ok && name != "" {
					if !namespaceSet[name] {
						namespaces = append(namespaces, name)
						namespaceSet[name] = true
					}
				}
			}
			continue
		default:
			continue
		}
		
		if ns.Cluster == clusterName && ns.Name != "" {
			if !namespaceSet[ns.Name] {
				namespaces = append(namespaces, ns.Name)
				namespaceSet[ns.Name] = true
			}
		}
	}
	
	return namespaces
}

func (cc *ClusterClient) RefreshNamespaces(ctx context.Context) error {
	namespaces, err := cc.Client.GetNamespaces(ctx)
	if err != nil {
		return err
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.Namespaces = namespaces
	return nil
}
