package auth

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileStoreUserAndGroupScopeUnion(t *testing.T) {
	hash, err := HashPassword("secret")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "auth.yaml")
	content := "version: v1\nusers:\n  alice:\n    passwordHash: " + hash + "\n    groups: [team-a]\n    scopes:\n      - cluster: cluster-a\n        namespaces: [alice-ns]\ngroups:\n  team-a:\n    scopes:\n      - cluster: cluster-b\n        namespaces: [shared]\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := store.Authenticate(context.Background(), " Alice ", "secret")
	if err != nil || principal.Username != "alice" {
		t.Fatalf("Authenticate() = %#v, %v", principal, err)
	}
	scope, err := store.ScopesFor(context.Background(), principal)
	if err != nil {
		t.Fatal(err)
	}
	if !scope.CanRead("cluster-a", "alice-ns") || !scope.CanRead("cluster-b", "shared") {
		t.Fatal("user and group scopes were not unioned")
	}
}
