package kubernetes

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

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
)

// Client represents a Kubernetes client
type Client struct {
	clientset *kubernetes.Clientset
	dynamic   dynamic.Interface
	config    *rest.Config
}

// NewClient creates a new Kubernetes client
func NewClient(kubeconfig string) (*Client, error) {
	var config *rest.Config
	var err error
	var clusterName string
	var contextName string

	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		config, err = rest.InClusterConfig()
		clusterName = "incluster"
	} else {
		if kubeconfig == "" {
			home := homedir.HomeDir()
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err == nil {
			// 获取context名
			if rawConfig, err2 := clientcmd.LoadFromFile(kubeconfig); err2 == nil {
				contextName = rawConfig.CurrentContext
				if contextName != "" {
					clusterName = contextName
				}
			}
		}
		if clusterName == "" {
			clusterName = "default"
		}
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

	// 只初始化 client，不再写入 DB
	return &Client{
		clientset: clientset,
		dynamic:   dynamicClient,
		config:    config,
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

// Report is a local struct for report data (替代 data.Report)
type Report struct {
	Type      string      `json:"type"`
	Cluster   string      `json:"cluster"`
	Namespace string      `json:"namespace"`
	Name      string      `json:"name"`
	Status    string      `json:"status,omitempty"`
	Data      interface{} `json:"data"`
}

// GetReportsByType returns reports of a specific type in the namespace
func (c *Client) GetReportsByType(ctx context.Context, reportType config.ReportKind, namespace string) ([]Report, error) {
	var reports []Report

	// List reports of this type
	items, err := c.ListReports(ctx, reportType, namespace)
	if err != nil {
		return nil, err
	}

	for _, item := range items {
		meta := map[string]interface{}{
			"name":      item.GetName(),
			"namespace": item.GetNamespace(),
			"uid":       item.GetUID(),
		}
		summary := map[string]interface{}{}
		repository := ""
		tag := ""
		scanner := ""
		age := ""
		// Try to extract summary fields
		if reportObj, found, _ := unstructured.NestedMap(item.Object, "report"); found {
			if sum, found, _ := unstructured.NestedMap(reportObj, "summary"); found {
				for k, v := range sum {
					summary[k] = v
				}
			}
			if art, found, _ := unstructured.NestedMap(reportObj, "artifact"); found {
				if repo, found, _ := unstructured.NestedString(art, "repository"); found {
					repository = repo
				}
				if t, found, _ := unstructured.NestedString(art, "tag"); found {
					tag = t
				}
			}
			if sc, found, _ := unstructured.NestedMap(reportObj, "scanner"); found {
				if s, found, _ := unstructured.NestedString(sc, "name"); found {
					scanner = s
				}
			}
			if created, found, _ := unstructured.NestedString(item.Object, "metadata", "creationTimestamp"); found {
				if t, err := time.Parse(time.RFC3339, created); err == nil {
					dur := time.Since(t)
					if dur.Hours() >= 24 {
						age = fmt.Sprintf("%dh", int(dur.Hours()))
					} else if dur.Hours() >= 1 {
						age = fmt.Sprintf("%dh", int(dur.Hours()))
					} else {
						age = fmt.Sprintf("%dm", int(dur.Minutes()))
					}
				}
			}
		}
		dataMap := map[string]interface{}{
			"meta":       meta,
			"summary":    summary,
			"repository": repository,
			"tag":        tag,
			"scanner":    scanner,
			"age":        age,
		}
		reports = append(reports, Report{
			Type:      reportType.Name,
			Cluster:   "default", // TODO: set actual cluster name if available
			Namespace: item.GetNamespace(),
			Name:      item.GetName(),
			Status:    "",
			Data:      dataMap,
		})
	}

	return reports, nil
}

// GetReportDetails retrieves detailed information about a specific report
func (c *Client) GetReportDetails(ctx context.Context, reportType config.ReportKind, namespace, name string) (*Report, error) {
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: reportType.Name,
	}

	report, err := c.dynamic.Resource(gvr).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get report from Kubernetes: %v", err)
	}

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

	return &Report{
		Type:      reportType.Name,
		Cluster:   "default",
		Namespace: namespace,
		Name:      name,
		Status:    status,
		Data:      report.Object,
	}, nil
}

// GetReports returns all reports in the specified namespace
func (c *Client) GetReports(ctx context.Context, namespace string) ([]Report, error) {
	var reports []Report

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

func (c *Client) Clientset() *kubernetes.Clientset {
	return c.clientset
}
