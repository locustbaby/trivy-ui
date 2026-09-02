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
helm repo add trivy-ui https://locustbaby.github.io/trivy-ui/
helm repo update
helm upgrade --install trivy-ui trivy-ui/trivy-ui
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
helm upgrade --install trivy-ui trivy-ui/trivy-ui \
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

The chart mounts the cache at `/cache` and sets `DATA_PATH` accordingly. If the
container is run directly, the default writable data directory is
`/tmp/trivy-ui-data`.

## Removed Namespace mode configuration

Collection is always cluster-wide. The old `DATA_ACCESS_MODE` and
`DATA_ACCESS_CLUSTERS` environment variables are no longer supported; remove
them from custom manifests and values files. User visibility is configured in
the Dashboard authentication file instead.
