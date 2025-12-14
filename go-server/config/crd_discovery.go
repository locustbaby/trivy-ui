package config

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	TrivyGroup        = "aquasecurity.github.io"
	DefaultAPIVersion = "v1alpha1"
)

var (
	globalRegistry *CRDRegistry
	registryOnce   sync.Once
)

type CRDRegistry struct {
	mu            sync.RWMutex
	reports       []ReportKind
	reportsByName map[string]*ReportKind
	lastRefresh   time.Time
	refreshTTL    time.Duration
}

func GetGlobalRegistry() *CRDRegistry {
	registryOnce.Do(func() {
		globalRegistry = &CRDRegistry{
			reportsByName: make(map[string]*ReportKind),
			refreshTTL:    5 * time.Minute,
		}
	})
	return globalRegistry
}

func (r *CRDRegistry) DiscoverCRDs(config *rest.Config) error {

	if err := r.DiscoverCRDsFromAPIResources(config); err == nil {
		return nil
	}

	return r.DiscoverCRDsFromCRDList(config)
}

func (r *CRDRegistry) DiscoverCRDsFromAPIResources(config *rest.Config) error {

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create clientset: %w", err)
	}

	apiResourceLists, err := clientset.Discovery().ServerPreferredResources()
	if err != nil {
		return fmt.Errorf("failed to get API resources: %w", err)
	}

	var reports []ReportKind
	reportsByName := make(map[string]*ReportKind)

	for _, apiResourceList := range apiResourceLists {

		groupVersion := apiResourceList.GroupVersion
		if !strings.HasPrefix(groupVersion, TrivyGroup+"/") {
			continue
		}

		parts := strings.Split(groupVersion, "/")
		if len(parts) != 2 {
			continue
		}

		for _, apiResource := range apiResourceList.APIResources {

			if strings.Contains(apiResource.Name, "/") {
				continue
			}

			reportKind := ReportKind{
				Name:       apiResource.Name,
				ShortName:  strings.ToLower(apiResource.Kind),
				APIVersion: groupVersion,
				Namespaced: apiResource.Namespaced,
				Kind:       apiResource.Kind,
			}

			reports = append(reports, reportKind)
			reportsByName[apiResource.Name] = &reports[len(reports)-1]
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.reports = reports
	r.reportsByName = reportsByName
	r.lastRefresh = time.Now()

	return nil
}

func (r *CRDRegistry) DiscoverCRDsFromCRDList(config *rest.Config) error {

	clientset, err := apiextensionsclientset.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create API extensions client: %w", err)
	}

	crdList, err := clientset.ApiextensionsV1().CustomResourceDefinitions().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list CRDs: %w", err)
	}

	var reports []ReportKind
	reportsByName := make(map[string]*ReportKind)

	for _, crd := range crdList.Items {

		if crd.Spec.Group != TrivyGroup {
			continue
		}

		version := DefaultAPIVersion
		if len(crd.Spec.Versions) > 0 {

			for _, v := range crd.Spec.Versions {
				if v.Served && v.Storage {
					version = v.Name
					break
				}
			}

			if version == DefaultAPIVersion && len(crd.Spec.Versions) > 0 {
				version = crd.Spec.Versions[0].Name
			}
		}

		namespaced := crd.Spec.Scope == apiextensionsv1.NamespaceScoped

		resourceName := crd.Spec.Names.Plural

		kind := crd.Spec.Names.Kind

		reportKind := ReportKind{
			Name:       resourceName,
			ShortName:  strings.ToLower(kind),
			APIVersion: fmt.Sprintf("%s/%s", crd.Spec.Group, version),
			Namespaced: namespaced,
			Kind:       kind,
		}

		reports = append(reports, reportKind)
		reportsByName[resourceName] = &reports[len(reports)-1]
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.reports = reports
	r.reportsByName = reportsByName
	r.lastRefresh = time.Now()

	return nil
}

func (r *CRDRegistry) GetAllReports() []ReportKind {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]ReportKind, len(r.reports))
	copy(result, r.reports)
	return result
}

func (r *CRDRegistry) GetReportByName(name string) *ReportKind {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if report, ok := r.reportsByName[name]; ok {

		reportCopy := *report
		return &reportCopy
	}
	return nil
}

func (r *CRDRegistry) RefreshIfNeeded(config *rest.Config) error {
	r.mu.RLock()
	needsRefresh := time.Since(r.lastRefresh) > r.refreshTTL || len(r.reports) == 0
	r.mu.RUnlock()

	if needsRefresh {
		return r.DiscoverCRDs(config)
	}
	return nil
}

func (r *CRDRegistry) GetLastRefreshTime() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastRefresh
}
