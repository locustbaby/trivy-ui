package kubernetes

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

type Client struct {
	clientset *kubernetes.Clientset
	dynamic   dynamic.Interface
	config    *rest.Config
	informer  *ReportInformerManager
}

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

	return &Client{
		clientset: clientset,
		dynamic:   dynamicClient,
		config:    config,
	}, nil
}

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

func parseAPIVersion(apiVersion string) (group, version string) {
	group = "aquasecurity.github.io"
	version = "v1alpha1"
	if apiVersion != "" {
		parts := strings.Split(apiVersion, "/")
		if len(parts) == 2 {
			group = parts[0]
			version = parts[1]
		}
	}
	return group, version
}

func (c *Client) ListReports(ctx context.Context, reportType config.ReportKind, namespace string) ([]unstructured.Unstructured, error) {

	if namespace != "" && !reportType.Namespaced {
		return nil, nil
	}

	group, version := parseAPIVersion(reportType.APIVersion)

	gvr := schema.GroupVersionResource{
		Group:    group,
		Version:  version,
		Resource: reportType.Name,
	}

	var list *unstructured.UnstructuredList
	var err error
	if reportType.Namespaced {
		list, err = c.dynamic.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
	} else {
		list, err = c.dynamic.Resource(gvr).List(ctx, metav1.ListOptions{})
	}
	if err != nil {

		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to list %s: %w", reportType.Kind, err)
	}

	return list.Items, nil
}

type Report struct {
	Type      string      `json:"type"`
	Cluster   string      `json:"cluster"`
	Namespace string      `json:"namespace"`
	Name      string      `json:"name"`
	Status    string      `json:"status,omitempty"`
	Data      interface{} `json:"data"`
}

func (c *Client) GetReportsByType(ctx context.Context, reportType config.ReportKind, namespace string) ([]Report, error) {
	var reports []Report

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
			Cluster:   "",
			Namespace: item.GetNamespace(),
			Name:      item.GetName(),
			Status:    "",
			Data:      dataMap,
		})
	}

	return reports, nil
}

func (c *Client) GetReportDetails(ctx context.Context, reportType config.ReportKind, namespace, name string) (*Report, error) {
	group, version := parseAPIVersion(reportType.APIVersion)

	gvr := schema.GroupVersionResource{
		Group:    group,
		Version:  version,
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
		Cluster:   "",
		Namespace: namespace,
		Name:      name,
		Status:    status,
		Data:      report.Object,
	}, nil
}

func (c *Client) GetReports(ctx context.Context, namespace string) ([]Report, error) {
	var reports []Report

	for _, reportType := range config.AllReports() {

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

func (c *Client) Config() *rest.Config {
	return c.config
}

func (c *Client) StartInformer(clusterName string, cacheUpdater CacheUpdater) error {
	if c.informer != nil {
		return nil
	}
	c.informer = NewReportInformerManager(c, clusterName, cacheUpdater)
	return c.informer.Start()
}

func (c *Client) StopInformer() {
	if c.informer != nil {
		c.informer.Stop()
		c.informer = nil
	}
}
