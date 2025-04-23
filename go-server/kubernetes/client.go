package kubernetes

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"trivy-ui/config"
	"trivy-ui/data"
)

// Client represents a Kubernetes client
type Client struct {
	clientset *kubernetes.Clientset
	dynamic   dynamic.Interface
	config    *rest.Config
	db        *data.DB
}

// NewClient creates a new Kubernetes client
func NewClient(kubeconfig string, db *data.DB) (*Client, error) {
	var config *rest.Config
	var err error

	// Check if running in cluster
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		config, err = rest.InClusterConfig()
	} else {
		// If kubeconfig is not provided, try to use the default one
		if kubeconfig == "" {
			home := homedir.HomeDir()
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	}

	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	// Get cluster information
	clusterInfo, err := clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster information: %w", err)
	}

	// Create cluster description
	clusterDesc := fmt.Sprintf("Kubernetes cluster with %d nodes", len(clusterInfo.Items))
	if len(clusterInfo.Items) > 0 {
		clusterDesc += fmt.Sprintf(", version: %s", clusterInfo.Items[0].Status.NodeInfo.KubeletVersion)
	}

	// Store cluster information in database
	clusterRepo := data.NewClusterRepository(db)
	if err := clusterRepo.SaveCluster(&data.Cluster{
		Name:        "default",
		Description: clusterDesc,
	}); err != nil {
		return nil, fmt.Errorf("failed to save cluster information: %w", err)
	}

	// Get and save namespaces
	namespaces, err := clientset.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get namespaces: %w", err)
	}

	for _, ns := range namespaces.Items {
		if err := clusterRepo.SaveNamespace(&data.Namespace{
			Cluster: "default",
			Name:    ns.Name,
		}); err != nil {
			return nil, fmt.Errorf("failed to save namespace %s: %w", ns.Name, err)
		}
	}

	return &Client{
		clientset: clientset,
		dynamic:   dynamicClient,
		config:    config,
		db:        db,
	}, nil
}

// GetNamespaces returns all namespaces in the cluster
func (c *Client) GetNamespaces(ctx context.Context) ([]string, error) {
	namespaces, err := c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var names []string
	for _, ns := range namespaces.Items {
		names = append(names, ns.Name)
	}
	return names, nil
}

// ListReports returns a list of reports of the specified type in the namespace
func (c *Client) ListReports(ctx context.Context, reportType config.ReportKind, namespace string) ([]unstructured.Unstructured, error) {
	// Skip cluster-wide reports when namespace is specified
	if namespace != "" && !reportType.Namespaced {
		return nil, nil
	}

	// Create dynamic client for the report type
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: reportType.Name,
	}

	// List reports
	var list *unstructured.UnstructuredList
	var err error
	if reportType.Namespaced {
		list, err = c.dynamic.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
		fmt.Println("List reports in namespace:", namespace)
	} else {
		list, err = c.dynamic.Resource(gvr).List(ctx, metav1.ListOptions{})
	}
	if err != nil {
		// Skip if the CRD is not installed
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to list %s: %w", reportType.Kind, err)
	}

	return list.Items, nil
}

// GetReportsByType returns reports of a specific type in the namespace
func (c *Client) GetReportsByType(ctx context.Context, reportType config.ReportKind, namespace string) ([]data.Report, error) {
	var reports []data.Report

	// List reports of this type
	items, err := c.ListReports(ctx, reportType, namespace)
	if err != nil {
		return nil, err
	}

	// Create basic report objects without fetching details
	for _, item := range items {
		// Extract status from the report if available
		status := "Unknown"
		if statusObj, ok := item.Object["status"].(map[string]interface{}); ok {
			if phase, ok := statusObj["phase"].(string); ok {
				status = phase
			}
		}

		report := data.Report{
			Type:      config.ReportType(reportType.Name),
			Cluster:   "default", // TODO: Get actual cluster name
			Namespace: item.GetNamespace(),
			Name:      item.GetName(),
			Status:    status,
			// Don't include full data to save resources
			Data: map[string]interface{}{
				"metadata": map[string]interface{}{
					"name":      item.GetName(),
					"namespace": item.GetNamespace(),
					"uid":       item.GetUID(),
				},
			},
		}
		reports = append(reports, report)
	}

	return reports, nil
}

// GetReportDetails retrieves detailed information about a specific report
func (c *Client) GetReportDetails(ctx context.Context, reportType config.ReportKind, namespace, name string) (*data.Report, error) {
	// Create dynamic client for the report type
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: reportType.Name,
	}

	// Get the report from Kubernetes
	report, err := c.dynamic.Resource(gvr).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get report from Kubernetes: %v", err)
	}

	// Log the report data for debugging
	fmt.Printf("Report from Kubernetes: %+v\n", report)

	// Extract status from the report
	status := "Unknown"
	if summary, ok := report.Object["report"].(map[string]interface{}); ok {
		if summaryData, ok := summary["summary"].(map[string]interface{}); ok {
			if criticalCount, ok := summaryData["criticalCount"].(float64); ok && criticalCount > 0 {
				status = "Critical"
			} else if highCount, ok := summaryData["highCount"].(float64); ok && highCount > 0 {
				status = "High"
			} else if mediumCount, ok := summaryData["mediumCount"].(float64); ok && mediumCount > 0 {
				status = "Medium"
			} else if lowCount, ok := summaryData["lowCount"].(float64); ok && lowCount > 0 {
				status = "Low"
			} else if noneCount, ok := summaryData["noneCount"].(float64); ok && noneCount > 0 {
				status = "None"
			}
		}
	}

	// Create report object with complete data
	reportObj := &data.Report{
		Type:      config.ReportType(reportType.Name),
		Cluster:   "default",
		Namespace: namespace,
		Name:      name,
		Status:    status,
		Data:      report.Object, // Save the complete report data
	}

	// Log the report object for debugging
	fmt.Printf("Returning report: %+v\n", reportObj)

	// Save report to database
	repo := data.NewRepository(c.db)
	if err := repo.SaveReport(reportObj); err != nil {
		return nil, fmt.Errorf("failed to save report: %v", err)
	}

	return reportObj, nil
}

// GetReports returns all reports in the specified namespace
func (c *Client) GetReports(ctx context.Context, namespace string) ([]data.Report, error) {
	var reports []data.Report

	// Get all report types from config
	for _, reportType := range config.AllReports {
		// Get reports of this type without fetching details
		typeReports, err := c.GetReportsByType(ctx, reportType, namespace)
		if err != nil {
			return nil, err
		}
		reports = append(reports, typeReports...)
	}

	return reports, nil
}
