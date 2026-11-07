package kubernetes

import (
	"context"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"

	"trivy-ui/utils"
)

var replicaSetGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}

// Pod-template hashes use Kubernetes' "safe" alphabet (no vowels, no 0/1/3),
// so "web-7d9f6b5c4" loses its hash while "web-server" keeps its name.
var templateHashSuffix = regexp.MustCompile(`^(.+)-[bcdfghjklmnpqrstvwxz2456789]{5,10}$`)

// Workload identifies what a report is really about: the Deployment behind a
// ReplicaSet, or the scanned resource itself.
type Workload struct {
	Kind    string `json:"kind,omitempty"`
	Name    string `json:"name"`
	Retired bool   `json:"retired,omitempty"`
}

type replicaSetInfo struct {
	ownerKind string
	ownerName string
	replicas  int64
}

// WorkloadResolver maps ReplicaSets to their owning Deployment and tells
// whether a ReplicaSet is retired (scaled to zero, kept only for rollback),
// using a metadata-only ReplicaSet informer. Without permission to list
// ReplicaSets it falls back to stripping the pod-template hash from the name.
type WorkloadResolver struct {
	mu          sync.RWMutex
	replicaSets map[string]replicaSetInfo
	enabled     bool
	synced      atomic.Bool
	generation  atomic.Uint64
	stop        chan struct{}
}

func newWorkloadResolver() *WorkloadResolver {
	return &WorkloadResolver{replicaSets: make(map[string]replicaSetInfo), stop: make(chan struct{})}
}

// StartWorkloadResolver starts the ReplicaSet informer for this cluster. It
// never fails: missing RBAC only disables the exact lookup.
func (c *Client) StartWorkloadResolver(clusterName string) *WorkloadResolver {
	if c.workloads != nil {
		return c.workloads
	}
	resolver := newWorkloadResolver()
	c.workloads = resolver
	if c.dynamic == nil {
		return resolver
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, err := c.dynamic.Resource(replicaSetGVR).List(ctx, metav1.ListOptions{Limit: 1})
	cancel()
	if err != nil {
		fields := map[string]interface{}{"cluster": clusterName, "error": err.Error()}
		if apierrors.IsForbidden(err) {
			fields["hint"] = "grant list/watch on apps/replicasets for Deployment names and retired-ReplicaSet detection"
		}
		utils.LogWarning("ReplicaSet lookup disabled; workload names are derived from report names", fields)
		return resolver
	}
	resolver.enabled = true

	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(c.dynamic, 10*time.Minute, metav1.NamespaceAll, nil)
	informer := factory.ForResource(replicaSetGVR).Informer()
	_ = informer.SetTransform(func(obj interface{}) (interface{}, error) {
		u, ok := obj.(*unstructured.Unstructured)
		if !ok {
			return obj, nil
		}
		replicas, _, _ := unstructured.NestedInt64(u.Object, "spec", "replicas")
		owners, _, _ := unstructured.NestedFieldNoCopy(u.Object, "metadata", "ownerReferences")
		slim := &unstructured.Unstructured{Object: map[string]interface{}{
			"apiVersion": u.GetAPIVersion(),
			"kind":       u.GetKind(),
			"metadata": map[string]interface{}{
				"name":            u.GetName(),
				"namespace":       u.GetNamespace(),
				"resourceVersion": u.GetResourceVersion(),
				"ownerReferences": owners,
			},
			"spec": map[string]interface{}{"replicas": replicas},
		}}
		return slim, nil
	})
	update := func(obj interface{}) {
		if u, ok := obj.(*unstructured.Unstructured); ok {
			resolver.set(u)
		}
	}
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    update,
		UpdateFunc: func(_, obj interface{}) { update(obj) },
		DeleteFunc: func(obj interface{}) {
			if u, ok := deletedUnstructured(obj); ok {
				resolver.remove(u.GetNamespace(), u.GetName())
			}
		},
	})
	factory.Start(resolver.stop)
	go func() {
		if cache.WaitForCacheSync(resolver.stop, informer.HasSynced) {
			resolver.synced.Store(true)
			resolver.generation.Add(1)
		}
	}()
	return resolver
}

// Workloads returns the cluster's resolver, or nil before it was started.
func (c *Client) Workloads() *WorkloadResolver {
	return c.workloads
}

func (r *WorkloadResolver) set(u *unstructured.Unstructured) {
	info := replicaSetInfo{}
	info.replicas, _, _ = unstructured.NestedInt64(u.Object, "spec", "replicas")
	for _, owner := range u.GetOwnerReferences() {
		if owner.Controller != nil && *owner.Controller {
			info.ownerKind, info.ownerName = owner.Kind, owner.Name
		}
	}
	key := u.GetNamespace() + "/" + u.GetName()
	r.mu.Lock()
	previous, existed := r.replicaSets[key]
	r.replicaSets[key] = info
	r.mu.Unlock()
	if !existed || previous != info {
		r.generation.Add(1)
	}
}

func (r *WorkloadResolver) remove(namespace, name string) {
	r.mu.Lock()
	delete(r.replicaSets, namespace+"/"+name)
	r.mu.Unlock()
	r.generation.Add(1)
}

// Generation changes whenever a lookup result may have changed.
func (r *WorkloadResolver) Generation() uint64 {
	if r == nil {
		return 0
	}
	return r.generation.Load()
}

// Resolve returns the workload a report belongs to, from the operator's
// trivy-operator.resource.* labels.
func (r *WorkloadResolver) Resolve(labels map[string]string, reportName string) Workload {
	kind := labels["trivy-operator.resource.kind"]
	name := labels["trivy-operator.resource.name"]
	namespace := labels["trivy-operator.resource.namespace"]
	if name == "" {
		return Workload{Name: reportName}
	}
	if kind != "ReplicaSet" {
		return Workload{Kind: kind, Name: name}
	}
	if r != nil && r.enabled {
		r.mu.RLock()
		info, found := r.replicaSets[namespace+"/"+name]
		r.mu.RUnlock()
		if found {
			workload := Workload{Kind: "ReplicaSet", Name: name, Retired: info.replicas == 0}
			if info.ownerName != "" {
				workload.Kind, workload.Name = info.ownerKind, info.ownerName
			}
			return workload
		}
		// Not (yet) known: only trust the absence once the informer synced.
		if r.synced.Load() {
			return Workload{Kind: "Deployment", Name: stripTemplateHash(name), Retired: true}
		}
	}
	return Workload{Kind: "Deployment", Name: stripTemplateHash(name)}
}

func stripTemplateHash(name string) string {
	if match := templateHashSuffix.FindStringSubmatch(name); match != nil {
		return match[1]
	}
	return name
}

func (r *WorkloadResolver) Stop() {
	if r == nil {
		return
	}
	select {
	case <-r.stop:
	default:
		close(r.stop)
	}
}
