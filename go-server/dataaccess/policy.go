package dataaccess

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"trivy-ui/auth"
)

type Policy struct {
	mode                string
	clusters            map[string]ClusterAccess
	fingerprint         string
	maxWatchStreams     int
	mu                  sync.RWMutex
	initializedClusters map[string]struct{}
}

type ClusterAccess struct {
	Namespaces []string `json:"namespaces"`
}

func NewFromEnv() (*Policy, error) {
	mode := strings.ToLower(strings.TrimSpace(getEnv("DATA_ACCESS_MODE", "cluster")))
	if mode != "cluster" && mode != "namespaces" {
		return nil, fmt.Errorf("unsupported data access mode %q", mode)
	}
	maxWatchStreams := 500
	if rawLimit := strings.TrimSpace(os.Getenv("DATA_ACCESS_MAX_WATCH_STREAMS")); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 {
			return nil, fmt.Errorf("DATA_ACCESS_MAX_WATCH_STREAMS must be a positive integer")
		}
		maxWatchStreams = parsed
	}
	policy := &Policy{mode: mode, clusters: map[string]ClusterAccess{}, maxWatchStreams: maxWatchStreams, initializedClusters: map[string]struct{}{}}
	if mode == "cluster" {
		policy.fingerprint = "cluster"
		return policy, nil
	}
	raw := os.Getenv("DATA_ACCESS_CLUSTERS")
	if raw == "" {
		return nil, fmt.Errorf("DATA_ACCESS_CLUSTERS is required in namespaces mode")
	}
	if err := json.Unmarshal([]byte(raw), &policy.clusters); err != nil {
		return nil, fmt.Errorf("parse DATA_ACCESS_CLUSTERS: %w", err)
	}
	if len(policy.clusters) == 0 {
		return nil, fmt.Errorf("at least one cluster is required in namespaces mode")
	}
	for cluster, access := range policy.clusters {
		namespaces := access.Namespaces
		if strings.TrimSpace(cluster) == "" || cluster != strings.TrimSpace(cluster) || len(namespaces) == 0 {
			return nil, fmt.Errorf("cluster %q must have a non-empty namespace list", cluster)
		}
		seen := map[string]struct{}{}
		for _, namespace := range namespaces {
			if namespace == "" || namespace == "*" || namespace == auth.ClusterScopedNamespace || strings.Contains(namespace, "*") {
				return nil, fmt.Errorf("cluster %q has invalid namespace %q", cluster, namespace)
			}
			if _, ok := seen[namespace]; ok {
				continue
			}
			seen[namespace] = struct{}{}
		}
		sort.Strings(namespaces)
		policy.clusters[cluster] = ClusterAccess{Namespaces: unique(namespaces)}
	}
	var parts []string
	for cluster, access := range policy.clusters {
		parts = append(parts, cluster+"="+strings.Join(access.Namespaces, ","))
	}
	sort.Strings(parts)
	policy.fingerprint = strings.Join(parts, ";")
	return policy, nil
}

func (p *Policy) IsRestricted() bool { return p != nil && p.mode == "namespaces" }

func (p *Policy) ShouldInitialize(cluster string) bool {
	return p == nil || !p.IsRestricted() || len(p.clusters[cluster].Namespaces) > 0
}

func (p *Policy) Namespaces(cluster string) []string {
	if p == nil || !p.IsRestricted() {
		return nil
	}
	return append([]string(nil), p.clusters[cluster].Namespaces...)
}

func (p *Policy) ConfiguredClusters() []string {
	if p == nil || !p.IsRestricted() {
		return nil
	}
	clusters := make([]string, 0, len(p.clusters))
	for cluster := range p.clusters {
		clusters = append(clusters, cluster)
	}
	sort.Strings(clusters)
	return clusters
}

func (p *Policy) CanRead(cluster, namespace string) bool {
	if p == nil || !p.IsRestricted() {
		return true
	}
	for _, allowed := range p.clusters[cluster].Namespaces {
		if allowed == namespace {
			return true
		}
	}
	return false
}

func (p *Policy) Scope() auth.ScopeSnapshot {
	if p == nil {
		return auth.UnrestrictedScope()
	}
	if !p.IsRestricted() {
		p.mu.RLock()
		clusters := make([]string, 0, len(p.initializedClusters))
		for cluster := range p.initializedClusters {
			clusters = append(clusters, cluster)
		}
		p.mu.RUnlock()
		if len(clusters) == 0 {
			return auth.UnrestrictedScope()
		}
		sort.Strings(clusters)
		rules := make([]auth.ScopeRule, 0, len(clusters))
		for _, cluster := range clusters {
			rules = append(rules, auth.ScopeRule{Cluster: cluster, Namespaces: []string{"*", auth.ClusterScopedNamespace}})
		}
		return auth.NewScopeSnapshot(rules)
	}
	rules := make([]auth.ScopeRule, 0, len(p.clusters))
	for cluster, access := range p.clusters {
		rules = append(rules, auth.ScopeRule{Cluster: cluster, Namespaces: access.Namespaces})
	}
	return auth.NewScopeSnapshot(rules)
}

func (p *Policy) Fingerprint() string {
	if p == nil {
		return "cluster"
	}
	if !p.IsRestricted() {
		return p.Scope().Fingerprint
	}
	return p.fingerprint
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

func (p *Policy) MaxWatchStreams() int {
	if p == nil {
		return 500
	}
	return p.maxWatchStreams
}

func unique(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
