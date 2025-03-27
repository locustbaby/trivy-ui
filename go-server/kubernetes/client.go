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

	// Try to get in-cluster config
	config, err = rest.InClusterConfig()
	if err != nil {
		// If not in-cluster, try to get kubeconfig from home directory
		kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			log.Fatalf("Error building kubeconfig: %s", err.Error())
		}
	}

	Clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Error creating Kubernetes client: %s", err.Error())
	}

	DynamicClient, err = dynamic.NewForConfig(config)
	if err != nil {
		log.Fatalf("Error creating dynamic client: %s", err.Error())
	}
}
