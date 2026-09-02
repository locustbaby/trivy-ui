package auth

import "testing"

func TestScopeSnapshotMatching(t *testing.T) {
	scope := NewScopeSnapshot([]ScopeRule{
		{Cluster: "cluster-a", Namespaces: []string{"payments"}},
		{Cluster: "cluster-a", Namespaces: []string{"*"}},
		{Cluster: "*", Namespaces: []string{"shared"}},
		{Cluster: "cluster-b", Namespaces: []string{"_"}},
	})
	tests := []struct {
		cluster, namespace string
		want               bool
	}{
		{"cluster-a", "payments", true},
		{"cluster-a", "other", true},
		{"cluster-b", "shared", true},
		{"cluster-c", "shared", true},
		{"cluster-b", "_", true},
		{"cluster-a", "_", false},
		{"cluster-c", "private", false},
	}
	for _, test := range tests {
		if got := scope.CanRead(test.cluster, test.namespace); got != test.want {
			t.Errorf("CanRead(%q, %q) = %v, want %v", test.cluster, test.namespace, got, test.want)
		}
	}
}

func TestUnrestrictedScopeIncludesClusterScopedReports(t *testing.T) {
	if !UnrestrictedScope().CanRead("cluster-a", "_") {
		t.Fatal("unrestricted scope must include cluster-scoped reports")
	}
}

func TestAccessSnapshotClusterVisibilityRequiresIntersection(t *testing.T) {
	access := NewAccessSnapshot(
		NewScopeSnapshot([]ScopeRule{{Cluster: "cluster-a", Namespaces: []string{"ns-a"}}}),
		NewScopeSnapshot([]ScopeRule{{Cluster: "cluster-a", Namespaces: []string{"ns-b"}}}),
	)
	if access.CanReadCluster("cluster-a") {
		t.Fatal("cluster with disjoint namespace scopes must not be visible")
	}

	access = NewAccessSnapshot(
		NewScopeSnapshot([]ScopeRule{{Cluster: "cluster-a", Namespaces: []string{"*"}}}),
		NewScopeSnapshot([]ScopeRule{{Cluster: "cluster-a", Namespaces: []string{"ns-a"}}}),
	)
	if !access.CanReadCluster("cluster-a") {
		t.Fatal("cluster/* must overlap with a namespaced source rule")
	}
}
