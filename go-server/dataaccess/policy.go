package dataaccess

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"trivy-ui/auth"
)

// Policy describes the cluster sources that were successfully initialized.
// User-level visibility is evaluated separately from this source scope.
type Policy struct {
	mu                  sync.RWMutex
	initializedClusters map[string]struct{}
}

func NewFromEnv() (*Policy, error) {
	if mode := strings.ToLower(strings.TrimSpace(os.Getenv("DATA_ACCESS_MODE"))); mode != "" && mode != "cluster" {
		return nil, fmt.Errorf("DATA_ACCESS_MODE=%q is no longer supported; collection is always cluster-wide", mode)
	}
	if strings.TrimSpace(os.Getenv("DATA_ACCESS_CLUSTERS")) != "" {
		return nil, fmt.Errorf("DATA_ACCESS_CLUSTERS is no longer supported; use authentication scopes to restrict user access")
	}
	return &Policy{initializedClusters: map[string]struct{}{}}, nil
}

func (p *Policy) Scope() auth.ScopeSnapshot {
	if p == nil {
		return auth.UnrestrictedScope()
	}
	p.mu.RLock()
	clusters := make([]string, 0, len(p.initializedClusters))
	for cluster := range p.initializedClusters {
		clusters = append(clusters, cluster)
	}
	p.mu.RUnlock()
	if len(clusters) == 0 {
		return auth.NewScopeSnapshot(nil)
	}
	sort.Strings(clusters)
	rules := make([]auth.ScopeRule, 0, len(clusters))
	for _, cluster := range clusters {
		rules = append(rules, auth.ScopeRule{Cluster: cluster, Namespaces: []string{"*", auth.ClusterScopedNamespace}})
	}
	return auth.NewScopeSnapshot(rules)
}

func (p *Policy) Fingerprint() string {
	if p == nil {
		return "cluster"
	}
	return p.Scope().Fingerprint
}

func (p *Policy) SetInitializedClusters(clusters []string) {
	if p == nil {
		return
	}
	initialized := make(map[string]struct{}, len(clusters))
	for _, cluster := range clusters {
		if strings.TrimSpace(cluster) != "" {
			initialized[cluster] = struct{}{}
		}
	}
	p.mu.Lock()
	p.initializedClusters = initialized
	p.mu.Unlock()
}
