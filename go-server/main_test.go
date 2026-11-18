package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"trivy-ui/auth"
)

func TestReadMountedKubeconfigConfinesSecretFiles(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "..revision")
	if err := os.Mkdir(data, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "cluster.yaml"), []byte("apiVersion: v1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..revision", filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..data", "cluster.yaml"), filepath.Join(dir, "cluster.yaml")); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.yaml")
	if err := os.WriteFile(outside, []byte("apiVersion: v1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "outside.yaml")); err != nil {
		t.Fatal(err)
	}
	if got, err := readMountedKubeconfig(dir, "cluster.yaml"); err != nil || string(got) != "apiVersion: v1\n" {
		t.Fatalf("projected Secret file = %q, %v", got, err)
	}
	for _, key := range []string{".", "..", "outside.yaml", "..data"} {
		if _, err := readMountedKubeconfig(dir, key); err == nil {
			t.Errorf("accepted invalid kubeconfig key %q", key)
		}
	}
}

func TestConfiguredClusterUsesReadKubeconfigAfterSecretRotation(t *testing.T) {
	dir := t.TempDir()
	for _, revision := range []string{"..old", "..new"} {
		data := filepath.Join(dir, revision)
		if err := os.Mkdir(data, 0700); err != nil {
			t.Fatal(err)
		}
		config := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: cluster
  cluster:
    server: https://%s.example.test
contexts:
- name: default
  context:
    cluster: cluster
    user: test-user
current-context: default
users:
- name: test-user
  user:
    tokenFile: token
`, revision[2:])
		if err := os.WriteFile(filepath.Join(data, "cluster.yaml"), []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(data, "token"), []byte("test-token"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"..data": "..old", "cluster.yaml": "..data/cluster.yaml", "token": "..data/token"} {
		if err := os.Symlink(target, filepath.Join(dir, link)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CLUSTER_SOURCES", `{"mounted":{"type":"kubeconfig","key":"cluster.yaml"}}`)
	before, err := loadConfiguredClusters(dir)
	if err != nil || len(before) != 1 {
		t.Fatalf("load mounted cluster: got %d clusters, %v", len(before), err)
	}
	if err := os.Symlink("..new", filepath.Join(dir, "..data_tmp")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "..data_tmp"), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	after, err := loadConfiguredClusters(dir)
	if err != nil || len(after) != 1 {
		t.Fatalf("load rotated cluster: got %d clusters, %v", len(after), err)
	}
	for _, item := range []struct {
		cluster clusterInfo
		host    string
	}{{before[0], "https://old.example.test"}, {after[0], "https://new.example.test"}} {
		client, err := newKubernetesClient(item.cluster)
		if err != nil {
			t.Fatal(err)
		}
		config := client.Config()
		if config.Host != item.host || config.BearerTokenFile != filepath.Join(dir, "token") {
			t.Errorf("client config: got host %q and token path %q; want host %q and a path under %q", config.Host, config.BearerTokenFile, item.host, dir)
		}
	}
}

func TestCORSSettingsFromEnv(t *testing.T) {
	t.Setenv("CORS_ALLOWED_ORIGINS", " https://dashboard.example.com, https://admin.example.com ")
	settings := corsSettingsFromEnv()
	if !settings.allowCredentials {
		t.Fatal("explicit origins must enable credentialed requests")
	}
	if len(settings.allowedOrigins) != 2 || settings.allowedOrigins[0] != "https://dashboard.example.com" || settings.allowedOrigins[1] != "https://admin.example.com" {
		t.Fatalf("allowed origins = %v", settings.allowedOrigins)
	}

	t.Setenv("CORS_ALLOWED_ORIGINS", "*")
	settings = corsSettingsFromEnv()
	if settings.allowCredentials {
		t.Fatal("wildcard origin must not enable credentials")
	}
}

func TestApplyCORSCookiePolicy(t *testing.T) {
	credentials := corsSettings{allowCredentials: true}
	cfg := auth.Config{CookieSameSite: "lax"}
	applyCORSCookiePolicy(&cfg, credentials, false)
	if cfg.CookieSameSite != "none" {
		t.Fatalf("derived SameSite policy = %q, want none", cfg.CookieSameSite)
	}

	cfg.CookieSameSite = "strict"
	applyCORSCookiePolicy(&cfg, credentials, true)
	if cfg.CookieSameSite != "strict" {
		t.Fatalf("explicit SameSite policy = %q, want strict", cfg.CookieSameSite)
	}
}
