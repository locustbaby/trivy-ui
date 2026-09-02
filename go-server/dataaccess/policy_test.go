package dataaccess

import "testing"

func TestLegacyNamespaceModeRejected(t *testing.T) {
	t.Setenv("DATA_ACCESS_MODE", "namespaces")
	t.Setenv("DATA_ACCESS_CLUSTERS", `{"cluster-a":{"namespaces":["team-a"]}}`)
	if _, err := NewFromEnv(); err == nil {
		t.Fatal("legacy namespace mode should be rejected")
	}
}

func TestLegacyClusterAllowlistRejected(t *testing.T) {
	t.Setenv("DATA_ACCESS_MODE", "cluster")
	t.Setenv("DATA_ACCESS_CLUSTERS", `{"cluster-a":{"namespaces":["team-a"]}}`)
	if _, err := NewFromEnv(); err == nil {
		t.Fatal("legacy cluster allowlist should be rejected")
	}
}

func TestClusterPolicyScopeUsesInitializedAliases(t *testing.T) {
	t.Setenv("DATA_ACCESS_MODE", "")
	t.Setenv("DATA_ACCESS_CLUSTERS", "")
	policy, err := NewFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	policy.SetInitializedClusters([]string{"cluster-b", "cluster-a"})
	scope := policy.Scope()
	if !scope.CanRead("cluster-a", "tenant") || !scope.CanRead("cluster-b", "_") {
		t.Fatal("initialized clusters should be readable in the source scope")
	}
	if scope.CanRead("removed", "tenant") {
		t.Fatal("removed cluster should not remain in the source scope")
	}
	if policy.Fingerprint() == "cluster" {
		t.Fatal("initialized cluster scope should have a content fingerprint")
	}
}
