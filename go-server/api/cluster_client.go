package api

import (
	"context"
	"fmt"
	"sync"

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
	namespaces, _ := client.GetNamespaces(context.Background())

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

	for _, ns := range namespaces {
		nsObj := Namespace{Cluster: clusterName, Name: ns}
		UpsertNamespaceToCache(nsObj)
	}

	return nil
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
