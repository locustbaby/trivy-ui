# Installation and configuration

## Prerequisites

- Kubernetes 1.19 or later
- Helm 3
- Trivy Operator installed in each cluster to be collected
- A kubeconfig or in-cluster ServiceAccount with read-only access to the
  required Trivy resources

## Install with Helm

The default chart installation creates the application ServiceAccount and
cluster-wide read-only RBAC resources:

```bash
helm upgrade --install trivy-ui oci://registry-1.docker.io/locustbaby/trivy-ui
```

The chart creates separate ClusterRoles for report access and API/CRD
discovery. `rbac.create: true` is the default.

To use the chart from the repository instead:

```bash
git clone https://github.com/locustbaby/trivy-ui.git
cd trivy-ui
helm upgrade --install trivy-ui ./charts/trivy-ui
```

## Configure cluster credentials

For the installation cluster, the chart-created ServiceAccount is used when
the application runs in-cluster. For additional clusters, mount kubeconfig
files in a Secret:

```bash
kubectl create secret generic kubeconfigs \
  --from-file=prod=/path/to/prod-kubeconfig \
  --from-file=staging=/path/to/staging-kubeconfig
```

Then install or upgrade with:

```bash
helm upgrade --install trivy-ui oci://registry-1.docker.io/locustbaby/trivy-ui \
  --set kubeconfigs.create=false \
  --set kubeconfigs.secretName=kubeconfigs
```


By default, Trivy UI discovers every kubeconfig context in the configured
directory. For stable aliases, use `clusterSources`:

```yaml
clusterSources:
  prod:
    type: kubeconfig
    key: prod
  staging:
    type: kubeconfig
    key: staging
```

Every initialized cluster is collected cluster-wide. Remote clusters do not
inherit the RBAC objects created in the installation cluster; grant equivalent
read-only permissions to the identity in each remote kubeconfig.

## Disable chart-created RBAC

Set `rbac.create: false` only when the ServiceAccount already has equivalent
permissions. Without those permissions, CRD discovery, namespace discovery,
listing, and watching reports will fail.

```yaml
rbac:
  create: false
```

## Persistent cache

The chart derives `DATA_PATH` from `cache.mountPath` (default: `/cache`) and
mounts the cache volume at that same path. Do not set `env.DATA_PATH` in Helm
values: it is intentionally chart-managed so the process path and mount cannot
drift apart.

Set `cache.enabled: false` to remove the size-limited cache volume. The chart
still mounts a writable pod-lifetime `emptyDir` at `/tmp/trivy-ui-data`, because
the server persists its cache while the pod runs and its root filesystem is
read-only. If the container is run directly, that is also the default data
directory.

## Removed Namespace mode configuration

Collection is always cluster-wide. The old `DATA_ACCESS_MODE` and
`DATA_ACCESS_CLUSTERS` environment variables are no longer supported; remove
them from custom manifests and values files. User visibility is configured in
the Dashboard authentication file instead.

## Standalone Docker container

You can also run Trivy UI as a standalone Docker container outside Kubernetes:

```bash
docker pull locustbaby/trivy-ui:v0.0.5

docker run -d \
  --name trivy-ui \
  -v /path/to/kubeconfigs:/kubeconfigs \
  -e KUBECONFIG_DIR=/kubeconfigs \
  -p 8080:8080 \
  locustbaby/trivy-ui:v0.0.5
```

- Mount the directory containing your kubeconfig file(s) to `/kubeconfigs`.
- Open `http://localhost:8080` in your browser.
- To enable authentication with Docker, see [Authentication and access control](02-authentication-and-access-control.md#4-run-with-docker-standalone).

## Environment variable reference

| Variable | Description | Default |
|---|---|---|
| `PORT` | HTTP listening port | `8080` |
| `LOG_LEVEL` | Logging level (`debug`, `info`, `warning`, `error`) | `info` |
| `STATIC_PATH` | Path to frontend assets directory | `trivy-dashboard/dist` |
| `KUBECONFIG_DIR` | Directory containing kubeconfig files | `/kubeconfigs` |
| `DATA_PATH` | Directory for cache snapshot persistence | `/tmp/trivy-ui-data` |
| `CORS_ALLOWED_ORIGINS` | Comma-separated browser origins for cross-origin setups | _(unset)_ |
| `AUTH_COOKIE_SAME_SITE` | Session-cookie policy: `lax`, `strict`, or `none` | `lax` |
| `ERROR_PAGE_CONFIG` | Structured JSON for support page shown on access/availability errors | _(unset)_ |
| `ERROR_PAGE_FILE` | Path to operator-provided custom HTML file served at `/error-page.html` | _(unset)_ |

## Custom error page

Operators can provide customized branding or contact instructions when an error or access restriction occurs.

### Structured Helm values (Recommended)
Configure `customErrorPage` directly in Helm `values.yaml` without needing custom HTML:

```yaml
customErrorPage:
  enabled: true
  title: "Security dashboard unavailable"
  message: "Contact the platform team for help:"
  items:
    - type: email
      label: Email
      value: sec-platform@example.com
    - type: link
      label: On-call chat
      value: https://chat.example.com/platform-oncall
    - type: link
      label: Runbook
      value: https://wiki.example.com/trivy-ui/runbook
```

### Static HTML file escape hatch
To provide an entirely custom HTML page, mount an HTML file and set `ERROR_PAGE_FILE`:

```bash
docker run -d \
  -v /path/to/error-page.html:/app/error-page.html:ro \
  -e ERROR_PAGE_FILE=/app/error-page.html \
  -p 8080:8080 \
  locustbaby/trivy-ui:v0.0.5
```


