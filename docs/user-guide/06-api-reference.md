# API Reference & Error Codes

Trivy UI provides a lightweight, RESTful JSON API for querying vulnerability reports, cluster statuses, and report types across Kubernetes clusters.

## Authentication & Headers

When local authentication is enabled (`AUTH_MODE=local`), all protected API endpoints require an active session cookie obtained via `/api/v1/auth/login`.

Every response includes an `X-Request-ID` header for tracing and correlation in structured access logs.

---

## V1 Endpoints

| Method | Path | Description | Access Level |
|--------|------|-------------|--------------|
| `GET` | `/api/v1/clusters` | List accessible clusters in the fleet | Public / Scoped |
| `GET` | `/api/v1/clusters/{cluster}/namespaces` | List accessible namespaces for a cluster | Public / Scoped |
| `GET` | `/api/v1/report-types` | List discovered Trivy Operator report types | Public / Scoped |
| `GET` | `/api/v1/reports` | List reports matching filter criteria (paginated) | Public / Scoped |
| `GET` | `/api/v1/reports/{cluster}/{type}/{namespace}/{name}` | Get complete report details (on-demand K8s query) | Public / Scoped |
| `GET` | `/api/v1/overview` | Aggregated severity counts, trends, and top workloads | Public / Scoped |
| `POST` | `/api/v1/auth/login` | Authenticate with username and password | Public |
| `POST` | `/api/v1/auth/logout` | Invalidate current session and clear cookie | Authenticated |
| `GET` | `/api/v1/auth/me` | Return current user profile, roles, and scopes | Public |
| `GET` | `/healthz` | Liveness health check | Public |
| `GET` | `/readyz` | Readiness health check (ready after initial K8s sync) | Public |

> [!NOTE]
> For cluster-scoped report details (e.g. `ClusterComplianceReport`), use the underscore `_` as the `{namespace}` path parameter:
> ```text
> GET /api/v1/reports/prod/clustervulnerabilityreports/_/cluster-report-name
> ```

---

## Query Parameters for `/api/v1/reports`

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `type` | `string` | Report CRD type (case-insensitive) | `?type=vulnerabilityreports` |
| `cluster` | `string` | Filter reports by cluster alias | `?cluster=prod` |
| `namespace` | `string` | Filter by one or more comma-separated namespaces | `?namespace=team-a,team-b` |
| `search` | `string` | Search report name, cluster, namespace, or container image | `?search=nginx` |
| `onlyVulnerable` | `boolean` | When `true`, filters out clean reports with zero findings | `?onlyVulnerable=true` |
| `page` | `integer` | Page number (1-indexed, default: `1`) | `?page=2` |
| `pageSize` | `integer` | Number of items per page (default: `20`, max: `100`) | `?pageSize=50` |

---

## Error Handling & Error Codes

Every API error response carries a machine-readable code in `error.type`, plus the `X-Request-ID` header value in `error.requestId` for log correlation:

```json
{
  "code": 1,
  "message": "access denied for namespace \"kube-system\"",
  "error": {
    "type": "ACCESS_DENIED",
    "requestId": "e1a90c0b821f5db6689d0b81c2d03ef4"
  }
}
```

### Standard Error Codes

| Error Code | HTTP Status | Description | Recommended Action |
|------------|-------------|-------------|--------------------|
| `INTERNAL_ERROR` | 500 | Unexpected server-side failure | Check backend logs with `requestId` |
| `VALIDATION_FAILED` | 400 | Invalid request parameter or missing required field | Verify query parameters or JSON body |
| `AUTH_REQUIRED` | 401 | Not authenticated (session cookie missing or expired) | Sign in via `/api/v1/auth/login` |
| `ACCESS_DENIED` | 403 | Authenticated user lacks scope for the requested resource | Check user scopes in `auth.yaml` |
| `REPORT_NOT_FOUND` | 404 | Specified report name does not exist | Verify cluster, namespace, and report name |
| `REPORT_AMBIGUOUS` | 400 | Query matches multiple reports across namespaces | Narrow query with explicit `namespace` |
| `PROVIDER_UNAVAILABLE` | 503 | Kubernetes API server unavailable or unreachable | Check cluster connectivity and kubeconfig |
| `DATA_INCOMPLETE` | 200 / 206 | Cache capacity exceeded; data may be partial | Increase cache size in Helm values |

---

## Example API Requests

### 1. List All Discovered Report Types
```bash
curl -s http://localhost:8080/api/v1/report-types | jq .
```

### 2. Query Vulnerability Reports with Filters
```bash
curl -s 'http://localhost:8080/api/v1/reports?cluster=prod&type=vulnerabilityreports&onlyVulnerable=true&pageSize=10' | jq .
```

### 3. Get Full Report Details
```bash
curl -s http://localhost:8080/api/v1/reports/prod/vulnerabilityreports/team-a/my-app-report | jq .
```

### 4. Health & Readiness Probe
```bash
curl -i http://localhost:8080/healthz
curl -i http://localhost:8080/readyz
```
