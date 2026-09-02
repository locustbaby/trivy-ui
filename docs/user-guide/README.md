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

## Recommended reading order

- Start with [Installation and configuration](01-installation.md).
- Add users with [Authentication and access control](02-authentication-and-access-control.md).
- Review remote cluster permissions in [Multi-cluster collection](03-multi-cluster-collection.md).
- Use [Operations and troubleshooting](04-operations-and-troubleshooting.md) when upgrading or diagnosing access problems.
