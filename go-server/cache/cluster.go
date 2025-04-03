// Cluster management functionality for the cache layer
package cache

import (
	"encoding/json"
	"errors"
	"sync"
)

// Cluster represents a Kubernetes cluster configuration
type Cluster struct {
	Name       string `json:"name"`
	KubeConfig string `json:"kubeConfig"`
}

var (
	clustersMutex      sync.RWMutex
	ErrClusterExists   = errors.New("cluster with this name already exists")
	ErrClusterNotFound = errors.New("cluster not found")
)

// ClusterKey returns the cache key for storing clusters
func ClusterKey() string {
	return "clusters"
}

// GetClusters retrieves all clusters from the cache
func GetClusters() ([]Cluster, error) {
	clustersMutex.RLock()
	defer clustersMutex.RUnlock()

	// Try to get clusters from cache
	data, found := Store.Get(ClusterKey())
	if !found {
		// If no clusters found, initialize empty array
		return []Cluster{}, nil
	}

	// Convert cache data to clusters array
	clustersData, ok := data.([]byte)
	if !ok {
		return []Cluster{}, errors.New("invalid clusters data format in cache")
	}

	var clusters []Cluster
	if err := json.Unmarshal(clustersData, &clusters); err != nil {
		return []Cluster{}, err
	}

	return clusters, nil
}

// SaveClusters stores clusters in the cache
func SaveClusters(clusters []Cluster) error {
	clustersMutex.Lock()
	defer clustersMutex.Unlock()

	// Convert clusters to JSON
	data, err := json.Marshal(clusters)
	if err != nil {
		return err
	}

	// Store in cache (never expires)
	Store.Set(ClusterKey(), data, -1)
	return nil
}

// AddCluster adds a new cluster to the cache
func AddCluster(cluster Cluster) error {
	// Validate cluster data
	if cluster.Name == "" {
		return errors.New("cluster name cannot be empty")
	}
	if cluster.KubeConfig == "" {
		return errors.New("kubeconfig cannot be empty")
	}

	// Get existing clusters
	clusters, err := GetClusters()
	if err != nil {
		return err
	}

	// Check if cluster with same name already exists
	for _, c := range clusters {
		if c.Name == cluster.Name {
			return ErrClusterExists
		}
	}

	// Add new cluster
	clusters = append(clusters, cluster)
	return SaveClusters(clusters)
}

// DeleteCluster removes a cluster from the cache
func DeleteCluster(name string) error {
	// Get existing clusters
	clusters, err := GetClusters()
	if err != nil {
		return err
	}

	// Find and remove the cluster
	found := false
	newClusters := []Cluster{}
	for _, c := range clusters {
		if c.Name != name {
			newClusters = append(newClusters, c)
		} else {
			found = true
		}
	}

	if !found {
		return ErrClusterNotFound
	}

	return SaveClusters(newClusters)
}

// GetCluster retrieves a specific cluster by name
func GetCluster(name string) (Cluster, error) {
	// Get existing clusters
	clusters, err := GetClusters()
	if err != nil {
		return Cluster{}, err
	}

	// Find the requested cluster
	for _, c := range clusters {
		if c.Name == name {
			return c, nil
		}
	}

	return Cluster{}, ErrClusterNotFound
}
