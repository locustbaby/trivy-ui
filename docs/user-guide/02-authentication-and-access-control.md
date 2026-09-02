# Authentication and access control

## Enable local authentication

Authentication is disabled by default. Enable the local file backend with a
Secret containing `auth.yaml` and a session secret:

```bash
cd go-server
go run . hash-password
```

Use the generated bcrypt hash in an `auth.yaml` file. Do not use the shortened
`$2b$12$...` value shown in examples as a real password hash.

```yaml
version: v1
users:
  alice:
    passwordHash: "$2b$12$REPLACE_WITH_THE_GENERATED_HASH"
    scopes:
      - cluster: prod
        namespaces:
          - team-a
      - cluster: prod
        namespaces:
          - _
groups:
  security:
    scopes:
      - cluster: staging
        namespaces:
          - "*"
```

Create the Secret and install or upgrade the chart:

```bash
kubectl create secret generic trivy-ui-auth \
  --from-file=auth.yaml=auth.yaml \
  --from-literal=session-secret="$(openssl rand -hex 32)"

helm upgrade --install trivy-ui trivy-ui/trivy-ui \
  --set auth.mode=local \
  --set auth.local.existingSecret=trivy-ui-auth
```

The Secret must contain the keys configured by `auth.local.configKey` and
`auth.local.sessionSecretKey`. The defaults are `auth.yaml` and
`session-secret`.

## Scope syntax

Each scope matches a `(cluster, namespace)` pair:

| Scope | Meaning |
|---|---|
| `prod` + `team-a` | `team-a` in the `prod` cluster |
| `prod` + `*` | All Namespaced reports in `prod` |
| `*` + `team-a` | `team-a` in every cluster |
| `*` + `*` | All Namespaced reports in every cluster |
| `prod` + `_` | Cluster-scoped reports in `prod` |
| `*` + `_` | Cluster-scoped reports in every cluster |

The special namespace `_` means Cluster-scoped reports. Namespace `*` does not
include `_`; users who need both kinds of reports need both scope entries.
Partial wildcards such as `prod-*` are not supported.

## Users and groups

A user's effective scope is the union of their direct `scopes` and the scopes
of every group listed in `groups`:

```yaml
version: v1
users:
  alice:
    passwordHash: "..."
    groups: [developers]
    scopes:
      - cluster: prod
        namespaces: [team-a]
groups:
  developers:
    scopes:
      - cluster: staging
        namespaces: [shared]
```

This user can read `prod/team-a` and `staging/shared`. Group membership does
not replace direct scopes; the two sets are combined.

## What is protected

Scopes are applied to report lists, report details, cluster and Namespace
discovery, overviews, trends, and report-type metadata. A user with only a
Namespaced scope cannot see Cluster-scoped reports. A user with only `_` can
see Cluster-scoped reports but not Namespaced reports.

When local authentication is disabled (`auth.mode: none`), the Dashboard does
not perform user login or per-user scope checks. Kubernetes RBAC remains the
collector's boundary.

## Cluster-scoped report URLs

Use `_` in the Namespace URL segment for a Cluster-scoped report:

```text
/api/v1/reports/prod/clustervulnerabilityreports/_/cluster-report
```

The server normalizes `_` to an empty Kubernetes Namespace before querying the
cluster-scoped resource.
