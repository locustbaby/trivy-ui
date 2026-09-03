# Trivy UI User Guide

This guide covers the normal production setup for Trivy UI:

1. Install the chart and provide credentials for the clusters that Trivy UI
   should collect.
2. Grant the backend ServiceAccount read-only Kubernetes permissions.
3. Enable local authentication when different Dashboard users need different
   views.
4. Configure user and group scopes in `auth.yaml`.

## Permission model

Trivy UI has two separate permission layers:

| Layer | Principal | Controls |
|---|---|---|
| Kubernetes RBAC | Backend ServiceAccount | Which CRDs and reports the collector can read |
| Dashboard authorization | Authenticated Dashboard user | Which initialized clusters, Namespaces, and report scopes the user can view |

The backend collects all discovered Namespaced and Cluster-scoped Trivy reports
from each initialized cluster. A user's request is allowed only when both the
Kubernetes data source and the user's Dashboard scope allow it.

There is no Namespace-only installation mode. Namespace restrictions for users
belong in `auth.yaml` scopes.

## User guide chapters

| Chapter | Focus |
|---|---|
| 📖 [**01. Installation & Configuration**](01-installation.md) | Helm chart deployment, standalone Docker, ingress setup, and resource requirements |
| 🔐 [**02. Authentication & Access Control**](02-authentication-and-access-control.md) | Password hashing, `auth.yaml` scopes, Web UI login experience, and API access |
| 🌐 [**03. Multi-Cluster Collection**](03-multi-cluster-collection.md) | Multi-cluster kubeconfig secrets, Fleet Hub cross-cluster overview, and cluster switching |
| 🛠️ [**04. Operations & Troubleshooting**](04-operations-and-troubleshooting.md) | 401 Unauthorized troubleshooting, network connectivity, proxy routing, and access logs |
| 📊 [**05. Dashboard Features & Navigation**](05-dashboard-features-and-navigation.md) | Resizable sidebar, Aqua semantic icons, 30-day trends, report filtering, and detail drawers |

## Recommended reading order

1. Start with [Installation and configuration](01-installation.md) to deploy the application.
2. Add users and permissions with [Authentication and access control](02-authentication-and-access-control.md).
3. Connect multiple clusters and explore Fleet Hub with [Multi-cluster collection](03-multi-cluster-collection.md).
4. Learn the UI workflows in [Dashboard features and navigation](05-dashboard-features-and-navigation.md).
5. Refer to [Operations and troubleshooting](04-operations-and-troubleshooting.md) when maintaining the deployment or diagnosing issues.


