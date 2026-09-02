# Trivy UI Helm Chart

A Helm chart for deploying Trivy UI Dashboard to Kubernetes clusters. This chart provides a complete deployment solution for the Trivy UI application with support for multi-cluster management.

For the complete user guide, including authentication and Dashboard scopes, see
the [project documentation](../../docs/README.md).

## Quick Install

### From Docker Hub (Recommended)

```bash
# Install directly from Docker Hub Helm registry
helm install my-trivy-ui oci://registry-1.docker.io/locustbaby/trivy-ui
```

### From GitHub Pages

```bash
# Add the Helm repository
helm repo add trivy-ui https://locustbaby.github.io/trivy-ui/
helm repo update

# Install the chart
helm install my-trivy-ui trivy-ui/trivy-ui
```

### From Local Chart

```bash
# Clone and install locally
git clone https://github.com/locustbaby/trivy-ui.git
cd trivy-ui/charts/trivy-ui
helm install my-trivy-ui .
```

## Features

- **Multi-Cluster Support**: Manage multiple Kubernetes clusters through kubeconfig files
- **RBAC Integration**: Automatic creation of required RBAC resources
- **Flexible Configuration**: Extensive customization options through values.yaml
- **Production Ready**: Includes health checks and resource limits
- **Ingress Support**: Built-in Ingress configuration with TLS support
- **Optional Local Authentication**: YAML users, bcrypt passwords, groups, and multi-cluster user scopes
- **Cluster-wide Collection**: Collects Namespaced and Cluster-scoped Trivy reports with read-only RBAC

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- Access to one or more Kubernetes clusters with Trivy Operator installed
- kubectl configured with cluster access

## Quick Start

### Basic Installation

```bash
# Clone the repository
git clone https://github.com/locustbaby/trivy-ui.git
cd trivy-ui/charts/trivy-ui

# Install with default settings
helm install my-trivy-ui .
```

### With Custom Values

```bash
# Create a custom values file
cat > my-values.yaml << EOF
ingress:
  enabled: true
  hosts:
    - host: trivy-ui.example.com
      paths:
        - path: /
          pathType: Prefix
resources:
  limits:
    memory: 256Mi
    cpu: 200m
EOF

# Install with custom values
helm install my-trivy-ui . -f my-values.yaml
```

## Configuration

### Multi-Cluster Setup

The chart supports multiple clusters by mounting kubeconfig files as a secret:

1. **Prepare your kubeconfig files:**
   ```bash
   # Each file should contain a single cluster's kubeconfig
   ls -la /path/to/kubeconfigs/
   # cluster1-kubeconfig
   # cluster2-kubeconfig
   # cluster3-kubeconfig
   ```

2. **Create a secret with your kubeconfig files:**
   ```bash
   kubectl create secret generic kubeconfigs \
     --from-file=cluster1=/path/to/cluster1-kubeconfig \
     --from-file=cluster2=/path/to/cluster2-kubeconfig \
     --from-file=cluster3=/path/to/cluster3-kubeconfig
   ```

3. **Install the chart:**
   ```bash
   helm install my-trivy-ui . \
     --set kubeconfigs.create=false \
     --set kubeconfigs.secretName=kubeconfigs
   ```

### Environment Variables

Configure application behavior through environment variables:

```yaml
env:
  # Directory containing kubeconfig files
  KUBECONFIG_DIR: "/kubeconfigs"
  # Path to static frontend assets
  STATIC_PATH: "trivy-dashboard/dist"
  # Enable debug logging
  LOG_LEVEL: "info"
  # HTTP port (optional, default 8080)
  PORT: "8080"
```

### Local Authentication

Authentication is disabled by default. To enable it, create one Secret containing an `auth.yaml` key and a random `session-secret` key:

```yaml
auth:
  mode: local
  local:
    backend: file
    existingSecret: trivy-ui-auth
    configKey: auth.yaml
    sessionSecretKey: session-secret
  session:
    duration: 12h
    cookieSecure: true
```

The `auth.yaml` file grants the union of direct User scopes and Group scopes:

```yaml
version: v1
users:
  alice:
    passwordHash: "$2b$12$..."
    groups: [team-a]
    scopes:
      - cluster: cluster-a
        namespaces: [alice-ns]
groups:
  team-a:
    scopes:
      - cluster: cluster-b
        namespaces: [shared]
```

Scopes match the complete `(cluster, namespace)` pair. `cluster-a/*` means all
Namespaced reports in `cluster-a`; `*/shared` means the `shared` Namespace in
every Cluster; and `*/*` means all Namespaced reports in every Cluster. The
special Namespace `_` represents Cluster-scoped reports, so use `cluster-a/_`
or `*/_` for those reports. Namespace `*` never includes `_`, and partial
patterns such as `prod-*` are not supported.

Generate a bcrypt hash with:

```bash
go-server hash-password
```

### Cluster-wide collection and user access

The chart installs a cluster-wide read-only `ClusterRole` and
`ClusterRoleBinding` for the UI ServiceAccount. This allows the backend to
collect both Namespaced and Cluster-scoped Trivy reports across the configured
clusters. The discovery role is separate and only covers CRD/API discovery.

When local authentication is enabled, restrict each UI user with `scopes` in
`auth.yaml`. Kubernetes RBAC controls the backend ServiceAccount; user scopes
control what an authenticated UI user can list, inspect, and aggregate. For a
Cluster-scoped report, include the special namespace `_` in the user's scope.
Remote kubeconfig clusters must have equivalent read-only RBAC configured by
the administrator in those clusters.

### Cache Capacity and Persistence

The default summary limit is 100,000 entries, aligned with the intended
multi-Cluster scale. Summary entries are authoritative business data: the
application does not randomly evict them when the limit is reached. New
reports are rejected and the affected Cluster is marked incomplete, so queries
that depend on it return `DATA_INCOMPLETE` instead of silently showing partial
results.

The `snapshotMaxSize` limit is a hard persistence limit, not an additional
summary capacity. If a snapshot would exceed it, the previous snapshot is
retained and the in-memory data remains available. Size the limit and memory
request for the actual number of reports, Cluster/Namespace indexes, and the
256MiB detail cache. `emptyDir` survives a container restart but not Pod
replacement; use a PVC when cache recovery across Pod replacement is required.

### Ingress Configuration

Enable and configure Ingress for external access:

```yaml
ingress:
  enabled: true
  className: "nginx"
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: trivy-ui.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: trivy-ui-tls
      hosts:
        - trivy-ui.example.com
```

### Resource Management

Configure resource requests and limits:

```yaml
resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

### Security Context

Configure security settings:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL

podSecurityContext:
  fsGroup: 1000
```

## Advanced Configuration

### Custom Image

Use a custom image or private registry:

```yaml
image:
  repository: your-registry.com/trivy-ui
  tag: "v1.0.0"
  pullPolicy: Always

imagePullSecrets:
  - name: regcred
```

### Node Affinity

Deploy to specific nodes:

```yaml
nodeSelector:
  kubernetes.io/os: linux
  node-role.kubernetes.io/worker: "true"

affinity:
  nodeAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      nodeSelectorTerms:
        - matchExpressions:
            - key: kubernetes.io/os
              operator: In
              values:
                - linux
```

### Tolerations

Deploy to tainted nodes:

```yaml
tolerations:
  - key: "dedicated"
    operator: "Equal"
    value: "trivy"
    effect: "NoSchedule"
```

## Values Reference

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Image repository | `locustbaby/trivy-ui` |
| `image.tag` | Image tag | `v0.0.5` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `imagePullSecrets` | Image pull secrets | `[]` |
| `nameOverride` | Override chart name | `""` |
| `fullnameOverride` | Override full name | `""` |
| `serviceAccount.create` | Create service account | `true` |
| `serviceAccount.annotations` | Service account annotations | `{}` |
| `serviceAccount.name` | Service account name | `""` |
| `podAnnotations` | Pod annotations | `{}` |
| `podSecurityContext` | Pod security context | `{fsGroup: 65532}` |
| `securityContext` | Container security context | non-root, read-only root filesystem |
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `80` |
| `ingress.enabled` | Enable ingress | `false` |
| `ingress.className` | Ingress class name | `nginx` |
| `ingress.annotations` | Ingress annotations | `{}` |
| `ingress.hosts` | Ingress hosts | `[]` |
| `ingress.tls` | Ingress TLS | `[]` |
| `resources.limits.cpu` | CPU limit | `100m` |
| `resources.limits.memory` | Memory limit | `128Mi` |
| `resources.requests.cpu` | CPU request | `100m` |
| `resources.requests.memory` | Memory request | `64Mi` |
| `nodeSelector` | Node selector | `{}` |
| `tolerations` | Tolerations | `[]` |
| `affinity` | Affinity rules | `{}` |
| `env.KUBECONFIG_DIR` | Kubeconfig directory | `/kubeconfigs` |
| `env.STATIC_PATH` | Static assets path | `trivy-dashboard/dist` |
| `env.LOG_LEVEL` | Logging level | `info` |
| `env.CORS_ALLOWED_ORIGINS` | Credentialed cross-origin browser origins | `""` |
| `auth.mode` | Authentication mode (`none` or `local`) | `none` |
| `auth.session.cookieSameSite` | Session cookie policy (`lax`, `strict`, `none`); empty derives `none` for explicit CORS origins | `""` |
| `kubeconfigs.create` | Create kubeconfig secret | `true` |
| `kubeconfigs.enabled` | Mount the kubeconfig secret | `true` |
| `kubeconfigs.secretName` | Kubeconfig secret name | `kubeconfigs` |
| `kubeconfigs.data` | Kubeconfig data | `{}` |
| `clusterSources` | Explicit Cluster aliases and credential sources | `{}` |
| `cache.summary.maxEntries` | Maximum authoritative report summaries | `100000` |
| `cache.summary.snapshotMaxSize` | Maximum summary snapshot size | `512Mi` |
| `cache.detail.persist` | Persist full report details | `true` |
| `cache.detail.maxSize` | In-memory detail cache limit | `256Mi` |
| `rbac.create` | Create cluster-wide read-only RBAC resources | `true` |

## Installation Examples

### Development Environment

```bash
helm install trivy-ui-dev . \
  --set replicaCount=1 \
  --set resources.limits.memory=256Mi \
  --set env.LOG_LEVEL=debug
```

### Production Environment

```bash
helm install trivy-ui-prod . \
  --set replicaCount=3 \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=trivy-ui.company.com \
  --set resources.limits.memory=512Mi \
  --set resources.limits.cpu=500m
```

### Multi-Cluster Setup

```bash
# Create kubeconfig secret first
kubectl create secret generic kubeconfigs \
  --from-file=prod-cluster=/path/to/prod-kubeconfig \
  --from-file=staging-cluster=/path/to/staging-kubeconfig

# Install with multi-cluster support
helm install trivy-ui-multi . \
  --set kubeconfigs.create=false \
  --set kubeconfigs.secretName=kubeconfigs \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=trivy-ui.company.com
```

## Upgrading

### Upgrade to New Version

```bash
# Update the chart
helm repo update

# Upgrade the release
helm upgrade my-trivy-ui trivy-ui/trivy-ui

# Or upgrade from local chart
helm upgrade my-trivy-ui . --reuse-values
```

### Upgrade with New Values

```bash
# Upgrade with new configuration
helm upgrade my-trivy-ui . \
  --reuse-values \
  --set ingress.enabled=true \
  --set resources.limits.memory=512Mi
```

## Uninstalling

```bash
# Uninstall the release
helm uninstall my-trivy-ui

# Clean up RBAC resources (if created by chart)
kubectl delete clusterrole trivy-ui
kubectl delete clusterrolebinding trivy-ui

# Clean up kubeconfig secret (if created manually)
kubectl delete secret kubeconfigs
```

## Troubleshooting

### Check Installation Status

```bash
# Check release status
helm status my-trivy-ui

# List all releases
helm list

# Check pod status
kubectl get pods -l app.kubernetes.io/name=trivy-ui

# Check service status
kubectl get svc -l app.kubernetes.io/name=trivy-ui
```

### View Logs

```bash
# View pod logs
kubectl logs -l app.kubernetes.io/name=trivy-ui

# Follow logs
kubectl logs -f deployment/trivy-ui

# View logs from specific pod
kubectl logs <pod-name>
```

### Debug Issues

```bash
# Describe pod for details
kubectl describe pod -l app.kubernetes.io/name=trivy-ui

# Check events
kubectl get events --sort-by='.lastTimestamp'

# Verify kubeconfig mount
kubectl exec -it deployment/trivy-ui -- ls -la /kubeconfigs

# Check environment variables
kubectl exec -it deployment/trivy-ui -- env | grep -E "(KUBECONFIG|STATIC|LOG_LEVEL)"
```

### Common Issues

1. **Pod fails to start:**
   - Check if kubeconfig secret exists and is properly mounted
   - Verify RBAC permissions are correct
   - Check resource limits and requests

2. **Cannot access the UI:**
   - Verify service is running: `kubectl get svc`
   - Check ingress configuration if using ingress
   - Verify port forwarding: `kubectl port-forward svc/trivy-ui 8080:80`

3. **No clusters detected:**
   - Verify kubeconfig files are valid
   - Check if kubeconfig directory is properly mounted
   - Review application logs for cluster loading errors

4. **Permission denied:**
   - Ensure ClusterRole and ClusterRoleBinding are created
   - Verify ServiceAccount has correct permissions
   - Check if Trivy Operator is installed in target clusters

## Best Practices

### Security

1. **Use dedicated ServiceAccount:**
   ```yaml
   serviceAccount:
     create: true
     annotations:
       eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT:role/trivy-ui-role
   ```

2. **Enable security context:**
   ```yaml
   securityContext:
     runAsNonRoot: true
     readOnlyRootFilesystem: true
   ```

3. **Use network policies:**
   ```yaml
   # Create NetworkPolicy to restrict traffic
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: trivy-ui-network-policy
   spec:
     podSelector:
       matchLabels:
         app.kubernetes.io/name: trivy-ui
     policyTypes:
     - Ingress
     - Egress
   ```

### Performance

1. **Configure appropriate resources:**
   ```yaml
   resources:
     limits:
       cpu: 500m
       memory: 512Mi
     requests:
       cpu: 100m
       memory: 128Mi
   ```

2. **Use persistent caching:**
   - Consider using PersistentVolume for cache storage
   - Configure appropriate storage class

### Monitoring

1. **Add Prometheus annotations:**
   ```yaml
   podAnnotations:
     prometheus.io/scrape: "true"
     prometheus.io/port: "8080"
     prometheus.io/path: "/metrics"
   ```

2. **Configure health checks:**
   ```yaml
   # Health checks are enabled by default
   livenessProbe:
     httpGet:
       path: /
       port: http
   readinessProbe:
     httpGet:
       path: /
       port: http
   ```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Support

- **Issues**: [GitHub Issues](https://github.com/locustbaby/trivy-ui/issues)
- **Documentation**: [User guide](../../docs/README.md) · [Main README](../../README.md)
- **Discussions**: [GitHub Discussions](https://github.com/locustbaby/trivy-ui/discussions)
