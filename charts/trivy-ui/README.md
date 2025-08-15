# Trivy UI Helm Chart

A Helm chart for deploying Trivy UI Dashboard to Kubernetes clusters. This chart provides a complete deployment solution for the Trivy UI application with support for multi-cluster management.

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
- **Production Ready**: Includes health checks, resource limits, and autoscaling
- **Ingress Support**: Built-in Ingress configuration with TLS support

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
  DEBUG: "false"
  # HTTP port (optional, default 8080)
  PORT: "8080"
```

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

### Autoscaling

Enable horizontal pod autoscaling:

```yaml
autoscaling:
  enabled: true
  minReplicas: 1
  maxReplicas: 5
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80
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
| `image.tag` | Image tag | `v0.0.2` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `imagePullSecrets` | Image pull secrets | `[]` |
| `nameOverride` | Override chart name | `""` |
| `fullnameOverride` | Override full name | `""` |
| `serviceAccount.create` | Create service account | `true` |
| `serviceAccount.annotations` | Service account annotations | `{}` |
| `serviceAccount.name` | Service account name | `""` |
| `podAnnotations` | Pod annotations | `{}` |
| `podSecurityContext` | Pod security context | `{}` |
| `securityContext` | Container security context | `{}` |
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
| `autoscaling.enabled` | Enable autoscaling | `false` |
| `autoscaling.minReplicas` | Min replicas | `1` |
| `autoscaling.maxReplicas` | Max replicas | `100` |
| `autoscaling.targetCPUUtilizationPercentage` | CPU target | `80` |
| `autoscaling.targetMemoryUtilizationPercentage` | Memory target | `80` |
| `nodeSelector` | Node selector | `{}` |
| `tolerations` | Tolerations | `[]` |
| `affinity` | Affinity rules | `{}` |
| `env.KUBECONFIG_DIR` | Kubeconfig directory | `/kubeconfigs` |
| `env.STATIC_PATH` | Static assets path | `trivy-dashboard/dist` |
| `env.DEBUG` | Debug mode | `false` |
| `kubeconfigs.create` | Create kubeconfig secret | `true` |
| `kubeconfigs.secretName` | Kubeconfig secret name | `kubeconfigs` |
| `kubeconfigs.data` | Kubeconfig data | `{}` |
| `rbac.create` | Create RBAC resources | `true` |

## Installation Examples

### Development Environment

```bash
helm install trivy-ui-dev . \
  --set replicaCount=1 \
  --set resources.limits.memory=256Mi \
  --set env.DEBUG=true
```

### Production Environment

```bash
helm install trivy-ui-prod . \
  --set replicaCount=3 \
  --set autoscaling.enabled=true \
  --set autoscaling.minReplicas=2 \
  --set autoscaling.maxReplicas=10 \
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
kubectl exec -it deployment/trivy-ui -- env | grep -E "(KUBECONFIG|STATIC|DEBUG)"
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

2. **Enable autoscaling for production:**
   ```yaml
   autoscaling:
     enabled: true
     minReplicas: 2
     maxReplicas: 10
   ```

3. **Use persistent caching:**
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
- **Documentation**: [Main README](../README.md)
- **Discussions**: [GitHub Discussions](https://github.com/locustbaby/trivy-ui/discussions)

