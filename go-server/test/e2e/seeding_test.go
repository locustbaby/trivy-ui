//go:build e2e

// E2E suite that treats a kwok-provisioned API server as a real Kubernetes
// cluster: it seeds synthetic Trivy report CRs through the dynamic client,
// then validates the trivy-ui HTTP API against ground truth read back from
// the API server.
//
// Required env:
//
//	E2E_BASE_URL  - base URL of a running trivy-ui server (default http://127.0.0.1:8099)
//	KUBECONFIG    - kubeconfig pointing at the kwok cluster (default ~/.kube/config)
//	E2E_CONTEXTS  - comma-separated kubeconfig contexts to seed (default current context)
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"k8s.io/client-go/kubernetes"
)

const (
	group           = "aquasecurity.github.io"
	version         = "v1alpha1"
	seedLabel       = "trivy-ui.e2e/seed"
	seedLabelValue  = "true"
	readyTimeout    = 2 * time.Minute
	informerTimeout = 90 * time.Second
)

var baseURL string
var e2eHTTPClient = &http.Client{Timeout: 10 * time.Second}

func TestMain(m *testing.M) {
	baseURL = getenv("E2E_BASE_URL", "http://127.0.0.1:8099")
	ctx, cancel := context.WithTimeout(context.Background(), readyTimeout)
	defer cancel()
	if err := waitForReady(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "server never became ready at %s: %v\n", baseURL, err)
		os.Exit(1)
	}
	if err := seedAll(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "seeding failed: %v\n", err)
		os.Exit(1)
	}
	// The server may have started its informers before any CR existed (empty
	// cluster); wait until the created reports are visible through the API so
	// assertions never race with watch delivery.
	if err := waitForConvergence(informerTimeout); err != nil {
		fmt.Fprintf(os.Stderr, "seeded reports never became visible: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// waitForConvergence polls the list endpoint until every seeded
// vulnerabilityreport is visible, which implies all informers have caught up.
func waitForConvergence(timeout time.Duration) error {
	want := len(e2eContexts()) * len(namespaces) * vulnsPerNamespace
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := e2eHTTPClient.Get(baseURL + "/api/v1/reports?type=vulnerabilityreports&pageSize=1")
		if err == nil {
			var env struct {
				Data struct {
					Total int `json:"total"`
				} `json:"data"`
			}
			err = json.NewDecoder(resp.Body).Decode(&env)
			resp.Body.Close()
			if err == nil && env.Data.Total == want {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %d reports", want)
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func e2eContexts() []string {
	if raw := strings.TrimSpace(os.Getenv("E2E_CONTEXTS")); raw != "" {
		seen := make(map[string]struct{})
		contexts := make([]string, 0)
		for _, value := range strings.Split(raw, ",") {
			contextName := strings.TrimSpace(value)
			if contextName == "" {
				continue
			}
			if _, ok := seen[contextName]; ok {
				continue
			}
			seen[contextName] = struct{}{}
			contexts = append(contexts, contextName)
		}
		if len(contexts) > 0 {
			return contexts
		}
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if rawConfig, err := loadingRules.GetStartingConfig(); err == nil && rawConfig.CurrentContext != "" {
		return []string{rawConfig.CurrentContext}
	}
	return []string{""}
}

func waitForReady(ctx context.Context) error {
	deadline := time.Now().Add(readyTimeout)
	for time.Now().Before(deadline) {
		resp, err := e2eHTTPClient.Get(baseURL + "/readyz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("timeout")
}

// ---------------------------------------------------------------------------
// Dynamic client helpers: the API server is treated as production Kubernetes.
// ---------------------------------------------------------------------------

type gvrSet struct {
	Vulns        schema.GroupVersionResource
	ConfigAudit  schema.GroupVersionResource
	Secrets      schema.GroupVersionResource
	ClusterVulns schema.GroupVersionResource
}

func gvrs() gvrSet {
	gv := schema.GroupVersion{Group: group, Version: version}
	return gvrSet{
		Vulns:        gv.WithResource("vulnerabilityreports"),
		ConfigAudit:  gv.WithResource("configauditreports"),
		Secrets:      gv.WithResource("exposedsecretreports"),
		ClusterVulns: gv.WithResource("clustervulnerabilityreports"),
	}
}

func kubeConfigForContext(contextName string) (*rest.Config, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if contextName != "" {
		overrides := &clientcmd.ConfigOverrides{CurrentContext: contextName}
		return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides).ClientConfig()
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, nil).ClientConfig()
}

func kubeConfig() (*rest.Config, error) {
	return kubeConfigForContext(e2eContexts()[0])
}

func (s gvrSet) byName(resource string) schema.GroupVersionResource {
	switch resource {
	case "vulnerabilityreports":
		return s.Vulns
	case "configauditreports":
		return s.ConfigAudit
	case "exposedsecretreports":
		return s.Secrets
	case "clustervulnerabilityreports":
		return s.ClusterVulns
	}
	panic("unknown resource " + resource)
}

func dynamicClientFromEnv() (dynamic.Interface, error) {
	config, err := kubeConfig()
	if err != nil {
		return nil, fmt.Errorf("build kubeconfig: %w", err)
	}
	return dynamic.NewForConfig(config)
}

func dynamicClientForContext(contextName string) (dynamic.Interface, error) {
	config, err := kubeConfigForContext(contextName)
	if err != nil {
		return nil, fmt.Errorf("build kubeconfig for %s: %w", contextName, err)
	}
	return dynamic.NewForConfig(config)
}

func clientsetFromEnv() (*kubernetes.Clientset, error) {
	config, err := kubeConfig()
	if err != nil {
		return nil, fmt.Errorf("build kubeconfig: %w", err)
	}
	return kubernetes.NewForConfig(config)
}

func clientsetForContext(contextName string) (*kubernetes.Clientset, error) {
	config, err := kubeConfigForContext(contextName)
	if err != nil {
		return nil, fmt.Errorf("build kubeconfig for %s: %w", contextName, err)
	}
	return kubernetes.NewForConfig(config)
}

// ---------------------------------------------------------------------------
// Seeding: deterministic synthetic reports for EVERY report type, in volume.
// ---------------------------------------------------------------------------

var namespaces = []string{"team-a", "team-b", "team-c"}

// Volume constants shared by the seeder and the convergence check.
const (
	vulnsPerNamespace = 50
	configAuditPerNS  = 40
	secretsPerNS      = 30
	clusterVulnCount  = 40
)

var workloads = []string{
	"web-frontend", "api-server", "payment-gateway", "auth-service",
	"redis-cache", "postgres-db", "kafka-broker", "grafana-dash",
	"nginx-ingress", "worker-queue",
}

var repositories = []string{
	"library/nginx", "library/redis", "library/postgres", "debian",
	"node", "golang", "myorg/backend", "myorg/frontend",
}

type severityCounts struct{ critical, high, medium, low int }

func countsForIndex(i int) severityCounts {
	switch {
	case i%7 == 3: // ~14% clean workloads
		return severityCounts{}
	default:
		return severityCounts{
			critical: i % 4,
			high:     (i / 2) % 6,
			medium:   (i / 3) % 5,
			low:      i % 3,
		}
	}
}

func (c severityCounts) total() int { return c.critical + c.high + c.medium + c.low }

func vulnArray(counts severityCounts, salt int) []interface{} {
	vulns := make([]interface{}, 0, counts.total())
	appendSev := func(n int, severity string) {
		for j := 0; j < n; j++ {
			vulns = append(vulns, map[string]interface{}{
				"vulnerabilityID":  fmt.Sprintf("CVE-2024-%04d", salt*97+j*13+len(vulns)),
				"pkgName":          fmt.Sprintf("libpkg%d", (len(vulns)+salt)%12),
				"installedVersion": "1.2.3-r0",
				"fixedVersion":     "1.2.4-r0",
				"severity":         severity,
				"title":            "synthetic e2e vulnerability",
				"primaryURL":       "https://example.com/advisories",
			})
		}
	}
	appendSev(counts.critical, "CRITICAL")
	appendSev(counts.high, "HIGH")
	appendSev(counts.medium, "MEDIUM")
	appendSev(counts.low, "LOW")
	return vulns
}

func summaryMap(counts severityCounts) map[string]interface{} {
	return map[string]interface{}{
		"criticalCount": counts.critical,
		"highCount":     counts.high,
		"mediumCount":   counts.medium,
		"lowCount":      counts.low,
		"unknownCount":  0,
		"noneCount":     0,
	}
}

func artifact(i int) map[string]interface{} {
	repo := repositories[i%len(repositories)]
	return map[string]interface{}{
		"repository": repo,
		"tag":        fmt.Sprintf("1.%d.%d", i%9, i%13),
		"digest":     fmt.Sprintf("sha256:%064x", i),
	}
}

func reportEnvelope(kind string, i int, summary map[string]interface{}, results interface{}) map[string]interface{} {
	report := map[string]interface{}{
		"updateTimestamp": time.Now().UTC().Format(time.RFC3339),
		"scanner":         map[string]interface{}{"name": "trivy", "version": "0.58.0-e2e"},
		"artifact":        artifact(i),
	}
	if summary != nil {
		report["summary"] = summary
	}
	if results != nil {
		report["results"] = results
	}
	return map[string]interface{}{"report": report}
}

func cr(apiVersion, kind, name, namespace string, payload map[string]interface{}) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: payload}
	obj.SetAPIVersion(apiVersion)
	obj.SetKind(kind)
	obj.SetName(name)
	if namespace != "" {
		obj.SetNamespace(namespace)
	}
	obj.SetLabels(map[string]string{seedLabel: seedLabelValue})
	return obj
}

func workloadName(prefix string, nsIdx, i int) string {
	return fmt.Sprintf("%s-%d", workloads[(nsIdx*3+i)%len(workloads)], i)
}

// seedAll wipes previous seed data and recreates every report type in volume:
//   - vulnerabilityreports:        3 namespaces x 50 = 150
//   - configauditreports:          3 namespaces x 40 = 120
//   - exposedsecretreports:        3 namespaces x 30 =  90
//   - clustervulnerabilityreports: 40 (cluster-scoped)
//
// Edge cases are mixed into every type: clean reports, reports without a
// summary section and reports with an empty result set.
func seedAll(ctx context.Context) error {
	for clusterIndex, contextName := range e2eContexts() {
		if err := seedCluster(ctx, contextName, clusterIndex); err != nil {
			return fmt.Errorf("seed cluster %s: %w", contextName, err)
		}
	}
	return nil
}

func seedCluster(ctx context.Context, contextName string, clusterIndex int) error {
	cs, err := clientsetForContext(contextName)
	if err != nil {
		return err
	}
	for _, ns := range namespaces {
		if _, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: ns},
		}, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("create namespace %s: %w", ns, err)
		}
	}

	dc, err := dynamicClientForContext(contextName)
	if err != nil {
		return err
	}
	set := gvrs()
	seedOffset := clusterIndex * 1000
	namePrefix := fmt.Sprintf("cluster-%d-", clusterIndex)
	seedName := func(name string) string { return namePrefix + name }

	// Idempotency: drop everything seeded by a previous run first.
	if err := deleteAllSeeded(ctx, dc, set); err != nil {
		return err
	}

	for nsIdx, ns := range namespaces {
		for i := 0; i < vulnsPerNamespace; i++ {
			counts := countsForIndex(i + nsIdx + seedOffset)
			payload := reportEnvelope("vuln", i+seedOffset, summaryMap(counts), []interface{}{map[string]interface{}{
				"target":          fmt.Sprintf("%s (debian %d.%d)", repositories[i%len(repositories)], 12+clusterIndex, i%3),
				"class":           "os-pkgs",
				"type":            "debian",
				"vulnerabilities": vulnArray(counts, i+nsIdx*100+seedOffset),
			}})
			name := seedName(workloadName("vuln", nsIdx, i) + "-report")
			if _, err := dc.Resource(set.Vulns).Namespace(ns).Create(ctx, cr(group+"/v1alpha1", "VulnerabilityReport", name, ns, payload), metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
				return fmt.Errorf("create vuln %s/%s: %w", ns, name, err)
			}
		}
		for i := 0; i < configAuditPerNS; i++ {
			counts := countsForIndex(i + nsIdx + 5 + seedOffset)
			checks := make([]interface{}, 0, counts.total())
			appendCheck := func(n int, severity string) {
				for j := 0; j < n; j++ {
					checks = append(checks, map[string]interface{}{
						"id":       fmt.Sprintf("AVD-KSV-%04d", len(checks)),
						"title":    "synthetic e2e check",
						"severity": severity,
						"success":  false,
						"category": "Kubernetes Security Check",
					})
				}
			}
			// Results composition must match the summary counts exactly so the
			// seeded data is self-consistent.
			appendCheck(counts.critical, "CRITICAL")
			appendCheck(counts.high, "HIGH")
			appendCheck(counts.medium, "MEDIUM")
			appendCheck(counts.low, "LOW")
			successes := 8
			payload := reportEnvelope("configaudit", i+seedOffset, map[string]interface{}{
				"criticalCount": counts.critical,
				"highCount":     counts.high,
				"mediumCount":   counts.medium,
				"lowCount":      counts.low,
				"successCount":  successes,
				"failCount":     len(checks),
			}, []interface{}{map[string]interface{}{
				"target": fmt.Sprintf("deployment/%s", workloadName("ca", nsIdx, i)),
				"checks": checks,
			}})
			name := seedName(workloadName("ca", nsIdx, i) + "-config-report")
			if _, err := dc.Resource(set.ConfigAudit).Namespace(ns).Create(ctx, cr(group+"/v1alpha1", "ConfigAuditReport", name, ns, payload), metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
				return fmt.Errorf("create configaudit %s/%s: %w", ns, name, err)
			}
		}
		for i := 0; i < secretsPerNS; i++ {
			counts := countsForIndex(i + nsIdx + 11 + seedOffset)
			secrets := make([]interface{}, 0, counts.total())
			appendSecret := func(n int, severity string) {
				for j := 0; j < n; j++ {
					secrets = append(secrets, map[string]interface{}{
						"ruleID":   "aws-access-key-id",
						"category": "AWS",
						"severity": severity,
						"title":    "synthetic e2e secret",
						"match":    "AKIA****************",
					})
				}
			}
			// Results composition must match the summary counts exactly.
			appendSecret(counts.critical, "CRITICAL")
			appendSecret(counts.high, "HIGH")
			appendSecret(counts.medium, "MEDIUM")
			appendSecret(counts.low, "LOW")
			payload := reportEnvelope("secret", i+seedOffset, summaryMap(counts), []interface{}{map[string]interface{}{
				"target":  "requirements.txt",
				"secrets": secrets,
			}})
			name := seedName(workloadName("sec", nsIdx, i) + "-secret-report")
			if _, err := dc.Resource(set.Secrets).Namespace(ns).Create(ctx, cr(group+"/v1alpha1", "ExposedSecretReport", name, ns, payload), metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
				return fmt.Errorf("create secret %s/%s: %w", ns, name, err)
			}
		}
	}
	for i := 0; i < clusterVulnCount; i++ {
		counts := countsForIndex(i + 23 + seedOffset)
		payload := reportEnvelope("clustervuln", i+seedOffset, summaryMap(counts), []interface{}{map[string]interface{}{
			"target":          fmt.Sprintf("cluster-policy-%d-%d", clusterIndex, i),
			"class":           "os-pkgs",
			"type":            "debian",
			"vulnerabilities": vulnArray(counts, i+700+seedOffset),
		}})
		name := seedName(fmt.Sprintf("cluster-vuln-report-%03d", i))
		if _, err := dc.Resource(set.ClusterVulns).Create(ctx, cr(group+"/v1alpha1", "ClusterVulnerabilityReport", name, "", payload), metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("create clustervuln %s: %w", name, err)
		}
	}
	return nil
}

func deleteAllSeeded(ctx context.Context, dc dynamic.Interface, set gvrSet) error {
	listOpts := metav1.ListOptions{LabelSelector: seedLabel + "=" + seedLabelValue}
	for _, gvr := range []schema.GroupVersionResource{set.Vulns, set.ConfigAudit, set.Secrets} {
		for _, ns := range namespaces {
			if err := dc.Resource(gvr).Namespace(ns).DeleteCollection(ctx, metav1.DeleteOptions{}, listOpts); err != nil && !apierrors.IsNotFound(err) && !isNoMatchErr(err) {
				return fmt.Errorf("delete %s in %s: %w", gvr.Resource, ns, err)
			}
		}
	}
	if err := dc.Resource(set.ClusterVulns).DeleteCollection(ctx, metav1.DeleteOptions{}, listOpts); err != nil && !apierrors.IsNotFound(err) && !isNoMatchErr(err) {
		return fmt.Errorf("delete %s: %w", set.ClusterVulns.Resource, err)
	}
	return nil
}

func isNoMatchErr(err error) bool {
	return meta.IsNoMatchError(err)
}
