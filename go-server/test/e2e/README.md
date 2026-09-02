# E2E Tests (kwok)

End-to-end tests that run the real `trivy-ui` server against a
[kwok](https://kwok.sigs.k8s.io)-provisioned cluster. kwokctl starts a **real
kube-apiserver + etcd** locally, so CRD discovery, informer watches, list/apply
semantics and dynamic-client reads all behave exactly like production — only
the nodes are fake.

## What is covered

The suite seeds ~400 synthetic report CRs across **every report type**
(150 VulnerabilityReports, 120 ConfigAuditReports, 90 ExposedSecretReports,
40 cluster-scoped ClusterVulnerabilityReports) in three namespaces, including
edge cases (clean reports, reports without a summary, empty result sets), then
asserts:

- Clusters are discovered and fully synced; all four report types are found.
- **Pagination**: walking pages (`pageSize=7`) collects every seeded item
  exactly once — totals match ground truth read back from the API server, no
  duplicates, no losses, exact `hasNext` boundaries, out-of-range page returns
  an empty payload with the correct total.
- **Order stability across refreshes**: three consecutive full traversals plus
  a second traversal with a different page size produce byte-identical order;
  output equals lexicographic sort-key order.
- **Data correctness**: overview severity totals and per-type scanned counts
  equal sums computed from the CRs themselves; the detail endpoint returns the
  actual CR content for a known report.
- **Filters**: namespace (single/multi/spaced), `onlyVulnerable` and search are
  validated against expectations computed from the seeded CRs.
- **Error matrix**: unknown report type → `400 VALIDATION_FAILED`, unknown
  cluster / nonexistent report → `503 PROVIDER_UNAVAILABLE`, missing type param
  → `400 VALIDATION_FAILED`, invalid paging params degrade to safe defaults.
- **Live updates**: creating a CR via the dynamic client makes it appear
  through the informer watch within seconds; deleting it removes it.

## Running locally

```bash
# 1. Create a kwok cluster (requires Docker; kwok downloads apiserver/etcd)
kwokctl create cluster --name trivy-ui-e2e --kube-version v1.30.4

# 2. Point kubectl at it
kubectl config view --raw --minify --flatten > /tmp/kwok-kubeconfig.yaml
export KUBECONFIG=/tmp/kwok-kubeconfig.yaml

# 3. Apply the Trivy CRDs
kubectl apply -f go-server/test/e2e/fixtures/crds.yaml

# 4. Start the server against kwok
cd go-server
go build -o /tmp/trivy-ui-server .
PORT=8099 DATA_PATH=/tmp/trivy-ui-data STATIC_PATH=/tmp/trivy-ui-static \
KUBECONFIG=$KUBECONFIG nohup /tmp/trivy-ui-server &

# 5. Seed + assert
E2E_BASE_URL=http://127.0.0.1:8099 go test -tags e2e -v ./test/e2e/...

# Teardown
kwokctl delete cluster --name trivy-ui-e2e
```

CI runs the same steps automatically in the `e2e-kwok` job of
`.github/workflows/build.yaml`. The suite is behind the `e2e` build tag so it
never runs under plain `go test ./...`.
