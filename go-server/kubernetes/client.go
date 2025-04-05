package kubernetes

import (
	"log"
	"path/filepath"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// Kubernetes clients
var Clientset *kubernetes.Clientset
var DynamicClient dynamic.Interface

// InitClient initializes connection to Kubernetes API
func InitClient() {
	var config *rest.Config
	var err error
	var configPath string

	// Try to get in-cluster config
	config, err = rest.InClusterConfig()
	if err != nil {
		// If not in-cluster, try to get kubeconfig from home directory
		configPath = filepath.Join(homedir.HomeDir(), ".kube", "config")
		config, err = clientcmd.BuildConfigFromFlags("", configPath)
		if err != nil {
			log.Fatalf("Error building kubeconfig: %s", err.Error())
		}
	} else {
		// If in-cluster, use the default config path
		configPath = filepath.Join(homedir.HomeDir(), ".kube", "config")
	}

	Clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Error creating Kubernetes client: %s", err.Error())
	}

	DynamicClient, err = dynamic.NewForConfig(config)
	if err != nil {
		log.Fatalf("Error creating dynamic client: %s", err.Error())
	}

	// Extract cluster name from kubeconfig and store in cache
	extractAndStoreClusterName(configPath)
}

// extractAndStoreClusterName reads the kubeconfig file and extracts the cluster name
func extractAndStoreClusterName(configPath string) {
	// Load the kubeconfig file
	config, err := clientcmd.LoadFromFile(configPath)
	if err != nil {
		log.Printf("Error loading kubeconfig: %s", err.Error())
		return
	}

	// Get the current context
	currentContext := config.CurrentContext
	if currentContext == "" {
		log.Println("No current context found in kubeconfig")
		return
	}

	// Get the context
	context, exists := config.Contexts[currentContext]
	if !exists {
		log.Printf("Context %s not found in kubeconfig", currentContext)
		return
	}

	// Get the cluster name from the context
	clusterName := context.Cluster
	if clusterName == "" {
		log.Println("No cluster name found in context")
		return
	}

	// Get the cluster configuration
	cluster, exists := config.Clusters[clusterName]
	if !exists {
		log.Printf("Cluster %s not found in kubeconfig", clusterName)
		return
	}

	// Log cluster server URL for debugging
	log.Printf("Cluster %s server URL: %s", clusterName, cluster.Server)

	// Create a cluster object
	clusterObj := Cluster{
		Name:       clusterName,
		KubeConfig: configPath,
		Enable:     true, // 默认启用
	}

	// Check if cluster already exists in cache
	clusters, err := GetClusters()
	if err != nil {
		log.Printf("Error getting clusters from cache: %s", err.Error())
		return
	}

	// Check if cluster already exists
	exists = false
	for _, c := range clusters {
		if c.Name == clusterName {
			exists = true
			break
		}
	}

	// Add cluster to cache if it doesn't exist
	if !exists {
		if err := AddCluster(clusterObj); err != nil {
			log.Printf("Error adding cluster to cache: %s", err.Error())
		} else {
			log.Printf("Added cluster %s to cache", clusterName)
		}
	} else {
		log.Printf("Cluster %s already exists in cache", clusterName)
	}
}
