package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"trivy-ui/auth"
)

// ---------------------------------------------------------------------------
// Local-auth flow tests: login -> cookie -> scoped access -> logout, exercised
// through the real AuthMiddleware and handlers (no cluster connection needed).
// ---------------------------------------------------------------------------

type authUser struct {
	username string
	password string
	scopes   []auth.ScopeRule
}

func writeAuthFile(t *testing.T, users []authUser) string {
	t.Helper()
	type fileUser struct {
		PasswordHash string           `yaml:"passwordHash"`
		Scopes       []auth.ScopeRule `yaml:"scopes"`
	}
	builder := strings.Builder{}
	builder.WriteString("version: v1\nusers:\n")
	for _, u := range users {
		hash, err := bcrypt.GenerateFromPassword([]byte(u.password), bcrypt.MinCost)
		if err != nil {
			t.Fatalf("hash password: %v", err)
		}
		scopes := ""
		if len(u.scopes) > 0 {
			parts := make([]string, 0, len(u.scopes))
			for _, s := range u.scopes {
				ns := make([]string, 0, len(s.Namespaces))
				for _, n := range s.Namespaces {
					ns = append(ns, "        - \""+n+"\"")
				}
				parts = append(parts,
					"      - cluster: \""+s.Cluster+"\"\n        namespaces:\n"+strings.Join(ns, "\n"))
			}
			scopes = "\n    scopes:\n" + strings.Join(parts, "\n")
		}
		builder.WriteString("  " + u.username + ":\n    passwordHash: \"" + string(hash) + "\"" + scopes + "\n")
	}
	path := filepath.Join(t.TempDir(), "auth.yaml")
	if err := os.WriteFile(path, []byte(builder.String()), 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}
	return path
}

func newAuthService(t *testing.T, users []authUser) *auth.Service {
	t.Helper()
	svc, err := auth.NewService(auth.Config{
		Mode:            "local",
		Backend:         "file",
		FilePath:        writeAuthFile(t, users),
		SessionSecret:   "unit-test-secret-0123456789abcdef0123456789abcdef",
		SessionDuration: time.Hour,
		CookieSecure:    false,
	})
	if err != nil {
		t.Fatalf("new auth service: %v", err)
	}
	return svc
}

func newAuthTestServer(t *testing.T, authService *auth.Service, reports map[string][]Report) (*httptest.Server, *Handler) {
	t.Helper()
	cache := &stubCacheService{reports: reports}
	h := NewHandler(nil, cache, nil, NewQueryService(cache), nil, authService, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/login", h.Login)
	mux.HandleFunc("/api/v1/auth/logout", h.Logout)
	protected := http.NewServeMux()
	protected.HandleFunc("/api/v1/reports", h.GetReportsV1)
	protected.HandleFunc("/api/v1/clusters", h.GetClusters)
	mux.Handle("/", h.AuthMiddleware(protected))

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, h
}

func login(t *testing.T, serverURL, username, password string) *http.Response {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	resp, err := http.Post(serverURL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	return resp
}

func getWithCookies(t *testing.T, url string, cookies []*http.Cookie) (int, apiEnvelopeForAuth) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	var env apiEnvelopeForAuth
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("invalid JSON from %s: %v", url, err)
	}
	return resp.StatusCode, env
}

type apiEnvelopeForAuth struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Error   *struct {
		Type string `json:"type"`
	} `json:"error"`
	Data json.RawMessage `json:"data"`
}

var (
	allScope     = []auth.ScopeRule{{Cluster: "*", Namespaces: []string{"*", "_"}}}
	teamAScope   = []auth.ScopeRule{{Cluster: "prod", Namespaces: []string{"team-a"}}}
	clusterScope = []auth.ScopeRule{{Cluster: "prod", Namespaces: []string{"_"}}}
)

func authFlowReports() map[string][]Report {
	now := time.Now()
	mk := func(ns, name string) Report {
		return Report{Type: "vulns", Cluster: "prod", Namespace: ns, Name: name, UpdatedAt: now}
	}
	return map[string][]Report{
		"vulns": {
			mk("team-a", "allowed-one"),
			mk("team-a", "allowed-two"),
			mk("team-b", "forbidden-one"),
		},
		"cluster-vulns": {
			{Type: "cluster-vulns", Cluster: "prod", Name: "cluster-report", UpdatedAt: now},
		},
	}
}

func TestAuthFlow_RequiresLogin(t *testing.T) {
	server, _ := newAuthTestServer(t, newAuthService(t, []authUser{
		{username: "alice", password: "alice-pass", scopes: allScope},
	}), authFlowReports())

	status, env := getWithCookies(t, server.URL+"/api/v1/reports?type=vulns", nil)
	if status != http.StatusUnauthorized || env.Error == nil || env.Error.Type != "AUTH_REQUIRED" {
		t.Fatalf("unauthenticated: status=%d error=%+v, want 401 AUTH_REQUIRED", status, env.Error)
	}
}

func TestAuthFlow_LoginRejectsBadCredentials(t *testing.T) {
	server, _ := newAuthTestServer(t, newAuthService(t, []authUser{
		{username: "alice", password: "alice-pass", scopes: allScope},
	}), authFlowReports())

	resp := login(t, server.URL, "alice", "wrong-password")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad password: status=%d, want 401", resp.StatusCode)
	}
}

func TestAuthFlow_ScopedUserSeesOnlyAllowedNamespaces(t *testing.T) {
	server, _ := newAuthTestServer(t, newAuthService(t, []authUser{
		{username: "bob", password: "bob-pass", scopes: teamAScope},
	}), authFlowReports())

	resp := login(t, server.URL, "bob", "bob-pass")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: status=%d", resp.StatusCode)
	}
	cookies := resp.Cookies()
	resp.Body.Close()
	if len(cookies) == 0 {
		t.Fatal("login did not set a session cookie")
	}

	status, env := getWithCookies(t, server.URL+"/api/v1/reports?type=vulns&pageSize=50", cookies)
	if status != http.StatusOK || env.Code != 0 {
		t.Fatalf("scoped list: status=%d code=%d message=%q", status, env.Code, env.Message)
	}
	raw := strings.ToLower(string(env.Data))
	if !strings.Contains(raw, "allowed-one") || !strings.Contains(raw, "allowed-two") {
		t.Fatalf("scoped user should see team-a reports, got %s", raw)
	}
	if strings.Contains(raw, "forbidden-one") {
		t.Fatalf("scoped user must not see team-b reports, got %s", raw)
	}
}

func TestAuthFlow_UserWithoutScopeSeesNothing(t *testing.T) {
	server, _ := newAuthTestServer(t, newAuthService(t, []authUser{
		{username: "carol", password: "carol-pass"},
	}), authFlowReports())

	resp := login(t, server.URL, "carol", "carol-pass")
	cookies := resp.Cookies()
	resp.Body.Close()

	status, env := getWithCookies(t, server.URL+"/api/v1/reports?type=vulns", cookies)
	if status != http.StatusOK {
		t.Fatalf("list with no scope: status=%d", status)
	}
	if strings.Contains(strings.ToLower(string(env.Data)), "allowed-") || strings.Contains(string(env.Data), "forbidden-") {
		t.Fatalf("user without scope must see no reports, got %s", string(env.Data))
	}
}

func TestAuthFlow_NamespacedScopeCannotSeeClusterScopedReports(t *testing.T) {
	server, _ := newAuthTestServer(t, newAuthService(t, []authUser{
		{username: "bob", password: "bob-pass", scopes: teamAScope},
	}), authFlowReports())

	resp := login(t, server.URL, "bob", "bob-pass")
	cookies := resp.Cookies()
	resp.Body.Close()

	status, env := getWithCookies(t, server.URL+"/api/v1/reports?type=cluster-vulns", cookies)
	if status != http.StatusOK {
		t.Fatalf("cluster-scoped list: status=%d", status)
	}
	if strings.Contains(strings.ToLower(string(env.Data)), "cluster-report") {
		t.Fatalf("namespaced scope must not see cluster-scoped reports: %s", env.Data)
	}
}

func TestAuthFlow_ClusterScopeCanSeeClusterScopedReports(t *testing.T) {
	server, _ := newAuthTestServer(t, newAuthService(t, []authUser{
		{username: "dana", password: "dana-pass", scopes: clusterScope},
	}), authFlowReports())

	resp := login(t, server.URL, "dana", "dana-pass")
	cookies := resp.Cookies()
	resp.Body.Close()

	status, env := getWithCookies(t, server.URL+"/api/v1/reports?type=cluster-vulns", cookies)
	if status != http.StatusOK || !strings.Contains(strings.ToLower(string(env.Data)), "cluster-report") {
		t.Fatalf("cluster scope should see cluster-scoped report: status=%d data=%s", status, env.Data)
	}
}

func TestAuthFlow_LogoutInvalidatesSession(t *testing.T) {
	server, _ := newAuthTestServer(t, newAuthService(t, []authUser{
		{username: "alice", password: "alice-pass", scopes: allScope},
	}), authFlowReports())

	resp := login(t, server.URL, "alice", "alice-pass")
	cookies := resp.Cookies()
	resp.Body.Close()

	status, _ := getWithCookies(t, server.URL+"/api/v1/reports?type=vulns", cookies)
	if status != http.StatusOK {
		t.Fatalf("authenticated request before logout: status=%d", status)
	}

	logoutReq, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/auth/logout", nil)
	for _, c := range cookies {
		logoutReq.AddCookie(c)
	}
	logoutResp, err := http.DefaultClient.Do(logoutReq)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	defer logoutResp.Body.Close()

	// Sessions are stateless signed cookies: logout clears the cookie on the
	// client (Max-Age=-1) but cannot revoke it server-side. Pin both halves of
	// that contract so any change is a conscious decision.
	cleared := false
	for _, c := range logoutResp.Cookies() {
		if c.Name == auth.CookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("logout must set an expired session cookie")
	}
	status, _ = getWithCookies(t, server.URL+"/api/v1/reports?type=vulns", cookies)
	if status != http.StatusOK {
		t.Fatalf("replayed pre-logout cookie should remain valid until expiry (stateless sessions): status=%d", status)
	}
}
