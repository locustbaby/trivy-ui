package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"

	"trivy-ui/auth"
	"trivy-ui/config"
	"trivy-ui/kubernetes"
)

const rescanCluster = "rescan-test"

var vulnGVR = schema.GroupVersionResource{Group: "aquasecurity.github.io", Version: "v1alpha1", Resource: "vulnerabilityreports"}

type rescanFixture struct {
	router  *Router
	dynamic *fake.FakeDynamicClient
	updater kubernetes.CacheUpdater
}

func vulnReportObject(namespace, name, uid, resourceVersion string, updated time.Time) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "aquasecurity.github.io/v1alpha1",
		"kind":       "VulnerabilityReport",
		"metadata": map[string]interface{}{
			"name": name, "namespace": namespace, "uid": uid, "resourceVersion": resourceVersion,
		},
		"report": map[string]interface{}{
			"updateTimestamp": updated.UTC().Format(time.RFC3339),
			"summary":         map[string]interface{}{"criticalCount": float64(1), "highCount": float64(2)},
			"vulnerabilities": []interface{}{map[string]interface{}{"vulnerabilityID": "CVE-2026-0001", "severity": "CRITICAL"}},
		},
	}}
}

func (f *rescanFixture) addReport(t *testing.T, object *unstructured.Unstructured) {
	t.Helper()
	if _, err := f.dynamic.Resource(vulnGVR).Namespace(object.GetNamespace()).Create(context.Background(), object, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	f.setSummary(object)
}

// setSummary feeds a report into the cache the way the informer does.
func (f *rescanFixture) setSummary(object *unstructured.Unstructured) {
	body := object.Object["report"].(map[string]interface{})
	data := map[string]interface{}{
		"metadata": map[string]interface{}{"name": object.GetName(), "namespace": object.GetNamespace(), "uid": string(object.GetUID())},
		"report":   map[string]interface{}{"summary": body["summary"], "updateTimestamp": body["updateTimestamp"]},
	}
	f.updater.SetReport(rescanCluster, object.GetNamespace(), "vulnerabilityreports", object.GetName(),
		&kubernetes.Report{ResourceVersion: object.GetResourceVersion(), Data: data})
}

func newRescanFixture(t *testing.T, cfg RescanConfig) *rescanFixture {
	t.Helper()
	if err := InitCache(); err != nil {
		t.Skipf("cannot init cache: %v", err)
	}
	if cache := GetCache(); cache != nil {
		cache.ClearCluster(rescanCluster)
	}
	rescans = newRescanTracker()
	ConfigureRescan(cfg)
	t.Cleanup(func() {
		ConfigureRescan(RescanConfig{Types: defaultRescanTypes, Timeout: 6 * time.Hour, MaxBulk: 50, MaxPending: 100})
		rescans = newRescanTracker()
		if cache := GetCache(); cache != nil {
			cache.ClearCluster(rescanCluster)
		}
	})

	registry := config.NewStaticCRDRegistry([]config.ReportKind{{
		Name: "vulnerabilityreports", Kind: "VulnerabilityReport", APIVersion: "aquasecurity.github.io/v1alpha1", Namespaced: true,
	}})
	scheme := runtime.NewScheme()
	dynamicClient := fake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{vulnGVR: "VulnerabilityReportList"})
	cacheSvc := NewCacheServiceImpl()
	clusters := NewClusterRegistry(cacheSvc)
	clusters.clients[rescanCluster] = &ClusterClient{Name: rescanCluster, Client: kubernetes.NewClientFromDynamic(dynamicClient), Registry: registry, SyncState: "Synced"}

	authService, err := auth.NewService(auth.Config{Mode: "proxy", Proxy: auth.ProxyConfig{
		UserHeader: "Remote-User", GroupsHeader: "Remote-Groups", TrustedCIDRs: "192.0.2.0/24",
	}})
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter(nil, t.TempDir(), cacheSvc, clusters, registry, authService, nil)
	return &rescanFixture{router: router, dynamic: dynamicClient, updater: NewCacheUpdater(clusters)}
}

func (f *rescanFixture) do(t *testing.T, method, path, groups string, body interface{}, headers map[string]string) (*httptest.ResponseRecorder, Response) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	request := httptest.NewRequest(method, "http://security.example"+path, reader)
	request.Header.Set("Remote-User", "alice")
	request.Header.Set("Remote-Groups", groups)
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	f.router.ServeHTTP(recorder, request)
	var response Response
	_ = json.Unmarshal(recorder.Body.Bytes(), &response)
	return recorder, response
}

func errorType(response Response) string {
	if response.Error == nil {
		return ""
	}
	return response.Error.Type
}

func enabledRescanConfig() RescanConfig {
	return RescanConfig{Enabled: true, Groups: []string{"admins"}, Types: defaultRescanTypes, Timeout: 6 * time.Hour, MaxBulk: 50, MaxPending: 100}
}

const rescanPath = "/api/v1/reports/" + rescanCluster + "/vulnerabilityreports/default/replicaset-app-1-app/rescan"

func TestRescanDisabledByDefault(t *testing.T) {
	f := newRescanFixture(t, RescanConfig{Types: defaultRescanTypes, Timeout: time.Hour, MaxBulk: 50, MaxPending: 100})
	f.addReport(t, vulnReportObject("default", "replicaset-app-1-app", "uid-1", "1", time.Now()))
	recorder, response := f.do(t, http.MethodPost, rescanPath, "admins", nil, nil)
	if recorder.Code != http.StatusForbidden || errorType(response) != string(ErrRescanDisabled) {
		t.Fatalf("got %d %s, want 403 RESCAN_DISABLED", recorder.Code, errorType(response))
	}
}

func TestRescanRejectsWrongGroupAndCrossOrigin(t *testing.T) {
	f := newRescanFixture(t, enabledRescanConfig())
	f.addReport(t, vulnReportObject("default", "replicaset-app-1-app", "uid-1", "1", time.Now()))

	if recorder, _ := f.do(t, http.MethodPost, rescanPath, "dev", nil, nil); recorder.Code != http.StatusForbidden {
		t.Fatalf("user outside RESCAN_GROUPS: got %d, want 403", recorder.Code)
	}
	if recorder, _ := f.do(t, http.MethodPost, rescanPath, "admins", nil, map[string]string{"Origin": "https://evil.example"}); recorder.Code != http.StatusForbidden {
		t.Fatalf("cross-origin request: got %d, want 403", recorder.Code)
	}
	if recorder, _ := f.do(t, http.MethodPost, rescanPath, "admins", nil, map[string]string{"Sec-Fetch-Site": "same-site"}); recorder.Code != http.StatusForbidden {
		t.Fatalf("same-site (other subdomain) request: got %d, want 403", recorder.Code)
	}
	if _, err := f.dynamic.Resource(vulnGVR).Namespace("default").Get(context.Background(), "replicaset-app-1-app", metav1.GetOptions{}); err != nil {
		t.Fatalf("rejected requests must not delete the report: %v", err)
	}
}

func TestRescanKeepsLastResultUntilNewReportArrives(t *testing.T) {
	f := newRescanFixture(t, enabledRescanConfig())
	object := vulnReportObject("default", "replicaset-app-1-app", "uid-1", "1", time.Now())
	f.addReport(t, object)
	detailPath := "/api/v1/reports/" + rescanCluster + "/vulnerabilityreports/default/replicaset-app-1-app"
	// The user looks at the report first, which caches the full result.
	if recorder, _ := f.do(t, http.MethodGet, detailPath, "admins", nil, nil); recorder.Code != http.StatusOK {
		t.Fatalf("detail before rescan: %d %s", recorder.Code, recorder.Body.String())
	}

	recorder, response := f.do(t, http.MethodPost, rescanPath, "admins", nil, map[string]string{"Origin": "http://security.example", "Sec-Fetch-Site": "same-origin"})
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("rescan: got %d %s, want 202", recorder.Code, recorder.Body.String())
	}
	if _, err := f.dynamic.Resource(vulnGVR).Namespace("default").Get(context.Background(), "replicaset-app-1-app", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("report should be deleted to trigger the operator, got err=%v", err)
	}
	_ = response

	// The informer sees the deletion: the cached result must stay.
	f.updater.DeleteReport(rescanCluster, "default", "vulnerabilityreports", "replicaset-app-1-app")
	if _, found := GetCache().Get(reportKey(rescanCluster, "default", "vulnerabilityreports", "replicaset-app-1-app")); !found {
		t.Fatal("cached summary was removed while the rescan is pending")
	}

	recorder, response = f.do(t, http.MethodGet, "/api/v1/reports?type=vulnerabilityreports&cluster="+rescanCluster, "admins", nil, nil)
	if recorder.Code != http.StatusOK || !bytes.Contains(recorder.Body.Bytes(), []byte(`"rescan":{"requestedAt"`)) {
		t.Fatalf("list should mark the report as rescanning: %d %s", recorder.Code, recorder.Body.String())
	}

	recorder, _ = f.do(t, http.MethodGet, detailPath, "admins", nil, nil)
	if recorder.Code != http.StatusOK || !bytes.Contains(recorder.Body.Bytes(), []byte("CVE-2026-0001")) || !bytes.Contains(recorder.Body.Bytes(), []byte(`"requestedBy":"alice"`)) {
		t.Fatalf("detail should serve the last full result while rescanning: %d %s", recorder.Code, recorder.Body.String())
	}

	recorder, response = f.do(t, http.MethodGet, "/api/v1/rescan", "admins", nil, nil)
	status, _ := response.Data.(map[string]interface{})
	if recorder.Code != http.StatusOK || status["allowed"] != true || len(status["pending"].([]interface{})) != 1 {
		t.Fatalf("status: %d %s", recorder.Code, recorder.Body.String())
	}

	if recorder, _ = f.do(t, http.MethodPost, rescanPath, "admins", nil, nil); recorder.Code != http.StatusAccepted {
		t.Fatalf("repeated rescan should be idempotent, got %d", recorder.Code)
	}

	// The operator writes the new report.
	f.setSummary(vulnReportObject("default", "replicaset-app-1-app", "uid-2", "2", time.Now()))
	if rescans.count() != 0 {
		t.Fatal("pending rescan should end when the new report arrives")
	}
	recorder, _ = f.do(t, http.MethodGet, "/api/v1/reports?type=vulnerabilityreports&cluster="+rescanCluster, "admins", nil, nil)
	if bytes.Contains(recorder.Body.Bytes(), []byte(`"rescan"`)) {
		t.Fatalf("report should no longer be marked: %s", recorder.Body.String())
	}
}

func TestRescanWithoutCachedDetailServesSummary(t *testing.T) {
	f := newRescanFixture(t, enabledRescanConfig())
	f.addReport(t, vulnReportObject("default", "replicaset-app-1-app", "uid-1", "1", time.Now()))
	if recorder, _ := f.do(t, http.MethodPost, rescanPath, "admins", nil, nil); recorder.Code != http.StatusAccepted {
		t.Fatalf("rescan: got %d", recorder.Code)
	}
	f.updater.DeleteReport(rescanCluster, "default", "vulnerabilityreports", "replicaset-app-1-app")
	recorder, _ := f.do(t, http.MethodGet, "/api/v1/reports/"+rescanCluster+"/vulnerabilityreports/default/replicaset-app-1-app", "admins", nil, nil)
	body := recorder.Body.Bytes()
	if recorder.Code != http.StatusOK || !bytes.Contains(body, []byte(`"criticalCount":1`)) || !bytes.Contains(body, []byte(`"rescan"`)) || bytes.Contains(body, []byte("CVE-2026-0001")) {
		t.Fatalf("without a cached detail the summary is served, nothing is fetched: %d %s", recorder.Code, body)
	}
}

func TestRescanTimeoutDropsReportThatNeverReturns(t *testing.T) {
	f := newRescanFixture(t, enabledRescanConfig())
	f.addReport(t, vulnReportObject("default", "replicaset-app-1-app", "uid-1", "1", time.Now()))
	if recorder, _ := f.do(t, http.MethodPost, rescanPath, "admins", nil, nil); recorder.Code != http.StatusAccepted {
		t.Fatalf("rescan: got %d", recorder.Code)
	}
	f.updater.DeleteReport(rescanCluster, "default", "vulnerabilityreports", "replicaset-app-1-app")

	if expired := rescans.expire(time.Now().Add(time.Hour), 6*time.Hour); len(expired) != 0 {
		t.Fatalf("expired too early: %v", expired)
	}
	if expired := rescans.expire(time.Now().Add(7*time.Hour), 6*time.Hour); len(expired) != 1 {
		t.Fatalf("expected one expired rescan, got %v", expired)
	}
	if _, found := GetCache().Get(reportKey(rescanCluster, "default", "vulnerabilityreports", "replicaset-app-1-app")); found {
		t.Fatal("result of a workload that never came back must be removed after the timeout")
	}
}

func TestBulkRescanFiltersAndLimits(t *testing.T) {
	cfg := enabledRescanConfig()
	cfg.MaxBulk = 1
	f := newRescanFixture(t, cfg)
	f.addReport(t, vulnReportObject("default", "replicaset-old-1-app", "uid-old", "1", time.Now().Add(-48*time.Hour)))
	f.addReport(t, vulnReportObject("default", "replicaset-new-1-app", "uid-new", "1", time.Now()))
	f.addReport(t, vulnReportObject("other", "replicaset-x-1-app", "uid-x", "1", time.Now().Add(-48*time.Hour)))

	recorder, response := f.do(t, http.MethodPost, "/api/v1/rescan", "admins", map[string]interface{}{
		"cluster": rescanCluster, "namespaces": []string{"default", "other"}, "dryRun": true,
	}, nil)
	if data, _ := response.Data.(map[string]interface{}); recorder.Code != http.StatusOK || data["count"] != float64(3) {
		t.Fatalf("dry run: %d %s", recorder.Code, recorder.Body.String())
	}

	recorder, response = f.do(t, http.MethodPost, "/api/v1/rescan", "admins", map[string]interface{}{
		"cluster": rescanCluster, "namespaces": []string{"default", "other"},
	}, nil)
	if recorder.Code != http.StatusBadRequest || errorType(response) != string(ErrRescanLimit) {
		t.Fatalf("over the bulk limit: got %d %s", recorder.Code, recorder.Body.String())
	}

	recorder, response = f.do(t, http.MethodPost, "/api/v1/rescan", "admins", map[string]interface{}{
		"cluster": rescanCluster, "namespaces": []string{"default"}, "olderThan": "24h", "types": []string{"vulnerabilityreports"},
	}, nil)
	if data, _ := response.Data.(map[string]interface{}); recorder.Code != http.StatusAccepted || data["accepted"] != float64(1) {
		t.Fatalf("bulk rescan: %d %s", recorder.Code, recorder.Body.String())
	}
	if !rescans.holds(reportKey(rescanCluster, "default", "vulnerabilityreports", "replicaset-old-1-app")) ||
		rescans.holds(reportKey(rescanCluster, "default", "vulnerabilityreports", "replicaset-new-1-app")) {
		t.Fatal("only the report older than 24h should be rescanned")
	}

	recorder, _ = f.do(t, http.MethodPost, "/api/v1/rescan", "admins", map[string]interface{}{
		"cluster": rescanCluster, "types": []string{"clustercompliancereports"},
	}, nil)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("compliance reports are not rescannable, got %d", recorder.Code)
	}
}

func TestRescanStatusWithoutAuthentication(t *testing.T) {
	ConfigureRescan(enabledRescanConfig())
	t.Cleanup(func() {
		ConfigureRescan(RescanConfig{Types: defaultRescanTypes, Timeout: 6 * time.Hour, MaxBulk: 50, MaxPending: 100})
	})
	service, _ := auth.NewService(auth.Config{Mode: "none"})
	h := &Handler{auth: service}
	if canRescan(currentRescanConfig(), h, auth.Principal{Username: "anonymous"}) {
		t.Fatal("rescans need an authenticated identity")
	}
}

func TestSameOriginRequest(t *testing.T) {
	cases := []struct {
		origin, site string
		allowed      []string
		want         bool
	}{
		{"", "", nil, true},
		{"http://security.example", "same-origin", nil, true},
		{"https://SECURITY.example", "", nil, true},
		{"https://evil.example", "", nil, false},
		{"", "cross-site", nil, false},
		{"https://ui.example", "", []string{"https://ui.example"}, true},
		{"https://ui.example", "cross-site", []string{"https://ui.example"}, true},
		{"https://other.example", "cross-site", []string{"https://ui.example"}, false},
		{"null", "", nil, false},
	}
	for _, c := range cases {
		request := httptest.NewRequest(http.MethodPost, "http://security.example/api/v1/rescan", nil)
		if c.origin != "" {
			request.Header.Set("Origin", c.origin)
		}
		if c.site != "" {
			request.Header.Set("Sec-Fetch-Site", c.site)
		}
		if got := sameOriginRequest(request, c.allowed); got != c.want {
			t.Errorf("origin=%q site=%q: got %v, want %v", c.origin, c.site, got, c.want)
		}
	}
}
