# Operations and troubleshooting

## Upgrade

Upgrade the chart and keep the authentication Secret unchanged:

```bash
helm upgrade trivy-ui oci://registry-1.docker.io/locustbaby/trivy-ui \
  --reuse-values
```


Remove any old `DATA_ACCESS_MODE`, `DATA_ACCESS_CLUSTERS`, or Namespace-mode
values from deployment manifests before upgrading. The supported model is
always cluster-wide collection plus Dashboard user scopes.

## CORS and browser sessions

Same-origin deployments need no additional CORS configuration. For a separate
frontend origin, set the exact comma-separated origins:

```yaml
env:
  CORS_ALLOWED_ORIGINS: "https://dashboard.example.com"
```

Explicit origins enable credentialed browser requests. Avoid `*` when using
authenticated cross-origin requests. With `auth.session.cookieSameSite` left
empty, Trivy UI sets `SameSite=None` for this setup; secure cookies are
required. To override it, set `auth.session.cookieSameSite` to `lax`, `strict`,
or `none` (the last option also requires `auth.session.cookieSecure: true`).

## Health and readiness

- `/healthz` checks that the HTTP server is running.
- `/readyz` becomes ready after the initial Kubernetes warm-up.

With a persistent cache, the server can start serving cached data while the
Kubernetes clients initialize in the background.

## Common problems

### No clusters are visible

Check the kubeconfig mount, `KUBECONFIG_DIR`, `clusterSources`, and the current
context. Then inspect the server logs for kubeconfig parsing or client creation
errors.

### Reports are missing

Check Kubernetes permissions for both Namespaced and Cluster-scoped report
resources. Also verify that the Trivy Operator CRDs exist and that the
ServiceAccount can list them.

### A logged-in user sees no data

Check that the user's effective scope matches the initialized cluster alias.
For Cluster-scoped reports, add a namespace entry of `_`; `*` alone only means
all Namespaced reports.

### Login returns 401 Unauthorized

If credentials were confirmed but login fails:
1. Confirm that the password matches the hash configured in `auth.yaml`.
2. Confirm that the `auth.yaml` key and `session-secret` key exist in the mounted Secret.

### A user receives `ACCESS_DENIED`

The request is outside the user's Dashboard scope or outside the data source
scope. Check the user's direct and group scopes, then check the backend's
Kubernetes permissions and initialized cluster list.

### Details fail while lists work

List access and detail access both require a valid user scope, but details are
also fetched from Kubernetes on demand. Check the report name, the `_`
Namespace convention for Cluster-scoped reports, and the ServiceAccount's
`get` permission.

## Useful API checks

```bash
curl -i http://localhost:8080/healthz
curl -i http://localhost:8080/readyz
curl -s http://localhost:8080/api/v1/report-types
curl -s 'http://localhost:8080/api/v1/reports?type=vulnerabilityreports&pageSize=20'
```

When local authentication is enabled, send the session cookie returned by the
login endpoint with protected API requests.

