package dataaccess

import (
	"os"
	"testing"
)

func TestNamespacePolicyFromEnv(t *testing.T) {
	t.Setenv("DATA_ACCESS_MODE", "namespaces")
	t.Setenv("DATA_ACCESS_CLUSTERS", `{"cluster-a":{"namespaces":["ns-a","shared"]},"cluster-b":{"namespaces":["shared"]}}`)
	policy, err := NewFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !policy.CanRead("cluster-a", "ns-a") || policy.CanRead("cluster-a", "other") || policy.CanRead("cluster-b", "ns-a") {
		t.Fatal("namespace policy matched an unexpected scope")
	}
	if policy.CanRead("cluster-a", "_") {
		t.Fatal("namespace policy must not include cluster-scoped reports")
	}
}

func TestNamespacePolicyRejectsWildcard(t *testing.T) {
	t.Setenv("DATA_ACCESS_MODE", "namespaces")
	t.Setenv("DATA_ACCESS_CLUSTERS", `{"cluster-a":{"namespaces":["*"]}}`)
	if _, err := NewFromEnv(); err == nil {
		t.Fatal("wildcard namespace should be rejected")
	}
}

func TestClusterPolicyDefault(t *testing.T) {
	os.Unsetenv("DATA_ACCESS_MODE")
	os.Unsetenv("DATA_ACCESS_CLUSTERS")
	policy, err := NewFromEnv()
	if err != nil || policy.IsRestricted() || !policy.CanRead("cluster-a", "_") {
		t.Fatalf("default policy = %#v, %v", policy, err)
	}
}

func TestClusterPolicyScopeUsesInitializedAliases(t *testing.T) {
	os.Unsetenv("DATA_ACCESS_MODE")
	os.Unsetenv("DATA_ACCESS_CLUSTERS")
	policy, err := NewFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	policy.SetInitializedClusters([]string{"cluster-b", "cluster-a"})
	scope := policy.Scope()
	if !scope.CanRead("cluster-a", "tenant") || !scope.CanRead("cluster-b", "_") {
		t.Fatal("initialized clusters should be readable in cluster mode")
	}
	if scope.CanRead("removed", "tenant") {
		t.Fatal("removed cluster should not remain in the data source scope")
	}
	if policy.Fingerprint() == "cluster" {
		t.Fatal("initialized cluster scope should have a content fingerprint")
	}
}
