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
	clusterClients   = make(map[string]*ClusterClient)
	clusterClientsMu sync.RWMutex
)

type ClusterClient struct {
	Name         string
	Client       *kubernetes.Client
	APIServerURL string
	Version      string
	Namespaces   []string
	mu           sync.RWMutex
}

func GetClusterClient(clusterName string) *ClusterClient {
	clusterClientsMu.RLock()
	defer clusterClientsMu.RUnlock()
	return clusterClients[clusterName]
}

func GetAllClusterClients() map[string]*ClusterClient {
	clusterClientsMu.RLock()
	defer clusterClientsMu.RUnlock()
	result := make(map[string]*ClusterClient)
	for k, v := range clusterClients {
		result[k] = v
	}
	return result
}

func SetClusterClient(clusterName string, client *kubernetes.Client) error {
	apiServerURL := ""
	if restConfig := client.Config(); restConfig != nil {
		apiServerURL = restConfig.Host
	}
	version := ""
	if versionInfo, err := client.Clientset().Discovery().ServerVersion(); err == nil {
		version = versionInfo.GitVersion
	}
	
	// Try to get namespaces from K8s API with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	namespaces, err := client.GetNamespaces(ctx)
	cancel()
	
	// If failed, try to recover from cache
	if err != nil || len(namespaces) == 0 {
		namespaces = recoverNamespacesFromCache(clusterName)
	}

	clusterClientsMu.Lock()
	defer clusterClientsMu.Unlock()

	clusterClients[clusterName] = &ClusterClient{
		Name:         clusterName,
		Client:       client,
		APIServerURL: apiServerURL,
		Version:      version,
		Namespaces:   namespaces,
	}

	clusterInfo := Cluster{
		Name:        clusterName,
		Description: fmt.Sprintf("API Server: %s, version: %s", apiServerURL, version),
	}
	UpsertClusterToCache(clusterInfo)

	// Always update cache with namespaces (even if recovered from cache)
	for _, ns := range namespaces {
		nsObj := Namespace{Cluster: clusterName, Name: ns}
		UpsertNamespaceToCache(nsObj)
	}

	return nil
}

// recoverNamespacesFromCache tries to recover namespace list from cache
func recoverNamespacesFromCache(clusterName string) []string {
	cache := GetCache()
	if cache == nil {
		return nil
	}
	
	var namespaces []string
	namespaceSet := make(map[string]bool) // Use set to avoid duplicates
	
	items := cache.Items()
	for k, v := range items {
		if !strings.HasPrefix(k, "namespace:") {
			continue
		}
		
		var ns Namespace
		switch val := v.(type) {
		case Namespace:
			ns = val
		case CacheItem:
			// Try to extract Namespace from CacheItem.Value
			if nsVal, ok := val.Value.(Namespace); ok {
				ns = nsVal
			} else if nsMap, ok := val.Value.(map[string]interface{}); ok {
				// Handle map format
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
			// Handle direct map format
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
		
		// Handle Namespace struct format
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
