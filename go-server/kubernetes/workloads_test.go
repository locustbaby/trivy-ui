package kubernetes

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestStripTemplateHash(t *testing.T) {
	cases := map[string]string{
		"immich-db-774c8dc468":        "immich-db",
		"web-7d9f6b5c4":               "web",
		"coredns-5f69475449":          "coredns",
		"web-server":                  "web-server",
		"api-v2":                      "api-v2",
		"nohash":                      "nohash",
		"authelia-redis-5b684cdf67":   "authelia-redis",
		"n8n-postgres-5888899bdf":     "n8n-postgres",
		"machine-learning-74985b4658": "machine-learning",
	}
	for input, want := range cases {
		if got := stripTemplateHash(input); got != want {
			t.Errorf("stripTemplateHash(%q) = %q, want %q", input, got, want)
		}
	}
}

func replicaSet(namespace, name, owner string, replicas int64) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]interface{}{"spec": map[string]interface{}{"replicas": replicas}}}
	u.SetNamespace(namespace)
	u.SetName(name)
	if owner != "" {
		controller := true
		u.SetOwnerReferences([]metav1.OwnerReference{{Kind: "Deployment", Name: owner, Controller: &controller}})
	}
	return u
}

func rsLabels(namespace, name string) map[string]string {
	return map[string]string{
		"trivy-operator.resource.kind":      "ReplicaSet",
		"trivy-operator.resource.name":      name,
		"trivy-operator.resource.namespace": namespace,
	}
}

func TestWorkloadResolverResolve(t *testing.T) {
	var unavailable *WorkloadResolver
	if got := unavailable.Resolve(rsLabels("default", "web-7d9f6b5c4"), "replicaset-web-7d9f6b5c4-app"); got != (Workload{Kind: "Deployment", Name: "web"}) {
		t.Fatalf("heuristic fallback: %+v", got)
	}
	if got := unavailable.Resolve(map[string]string{"trivy-operator.resource.kind": "StatefulSet", "trivy-operator.resource.name": "db"}, "statefulset-db-db"); got != (Workload{Kind: "StatefulSet", Name: "db"}) {
		t.Fatalf("non-ReplicaSet kinds are kept: %+v", got)
	}
	if got := unavailable.Resolve(nil, "clusterrole-admin"); got != (Workload{Name: "clusterrole-admin"}) {
		t.Fatalf("reports without labels use the report name: %+v", got)
	}

	resolver := newWorkloadResolver()
	resolver.enabled = true
	resolver.set(replicaSet("default", "web-7d9f6b5c4", "web", 2))
	resolver.set(replicaSet("default", "web-6c8b7d5f9", "web", 0))
	if got := resolver.Resolve(rsLabels("default", "web-7d9f6b5c4"), ""); got != (Workload{Kind: "Deployment", Name: "web"}) {
		t.Fatalf("current ReplicaSet: %+v", got)
	}
	if got := resolver.Resolve(rsLabels("default", "web-6c8b7d5f9"), ""); got != (Workload{Kind: "Deployment", Name: "web", Retired: true}) {
		t.Fatalf("scaled-down ReplicaSet must be retired: %+v", got)
	}
	if got := resolver.Resolve(rsLabels("default", "gone-5f69475449"), ""); got.Retired {
		t.Fatalf("unknown ReplicaSet before sync must not be retired: %+v", got)
	}
	resolver.synced.Store(true)
	if got := resolver.Resolve(rsLabels("default", "gone-5f69475449"), ""); !got.Retired || got.Name != "gone" {
		t.Fatalf("deleted ReplicaSet after sync is retired: %+v", got)
	}

	before := resolver.Generation()
	resolver.set(replicaSet("default", "web-7d9f6b5c4", "web", 2))
	if resolver.Generation() != before {
		t.Fatal("an unchanged ReplicaSet must not bump the generation")
	}
	resolver.set(replicaSet("default", "web-7d9f6b5c4", "web", 0))
	if resolver.Generation() == before {
		t.Fatal("a scaled ReplicaSet must bump the generation")
	}
}
