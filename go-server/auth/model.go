package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const ClusterScopedNamespace = "_"

type Principal struct {
	Subject  string
	Username string
	Groups   []string
}

type ScopeRule struct {
	Cluster    string   `yaml:"cluster" json:"cluster"`
	Namespaces []string `yaml:"namespaces" json:"namespaces"`
}

type ScopeSnapshot struct {
	Rules       []ScopeRule `json:"rules"`
	Fingerprint string      `json:"fingerprint"`
}

type AccessSnapshot struct {
	User        ScopeSnapshot
	Source      ScopeSnapshot
	Fingerprint string
}

func NewAccessSnapshot(user, source ScopeSnapshot) AccessSnapshot {
	data, _ := json.Marshal([]string{user.Fingerprint, source.Fingerprint})
	digest := sha256.Sum256(data)
	return AccessSnapshot{User: user, Source: source, Fingerprint: hex.EncodeToString(digest[:])}
}

func (a AccessSnapshot) CanRead(cluster, namespace string) bool {
	return a.User.CanRead(cluster, namespace) && a.Source.CanRead(cluster, namespace)
}

func (a AccessSnapshot) CanReadCluster(cluster string) bool {
	for _, userRule := range a.User.Rules {
		for _, sourceRule := range a.Source.Rules {
			if scopeRulesOverlapForCluster(userRule, sourceRule, cluster) {
				return true
			}
		}
	}
	return false
}

func (a AccessSnapshot) IsUnrestricted() bool {
	return a.User.IsUnrestricted() && a.Source.IsUnrestricted()
}

func UnrestrictedScope() ScopeSnapshot {
	return NewScopeSnapshot([]ScopeRule{{Cluster: "*", Namespaces: []string{"*", ClusterScopedNamespace}}})
}

func NewScopeSnapshot(rules []ScopeRule) ScopeSnapshot {
	seen := make(map[string]struct{})
	normalized := make([]ScopeRule, 0, len(rules))
	for _, rule := range rules {
		namespaces := append([]string(nil), rule.Namespaces...)
		sort.Strings(namespaces)
		uniqueNamespaces := namespaces[:0]
		for _, namespace := range namespaces {
			if len(uniqueNamespaces) == 0 || uniqueNamespaces[len(uniqueNamespaces)-1] != namespace {
				uniqueNamespaces = append(uniqueNamespaces, namespace)
			}
		}
		key := rule.Cluster + "\x00" + strings.Join(uniqueNamespaces, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, ScopeRule{Cluster: rule.Cluster, Namespaces: uniqueNamespaces})
	}
	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].Cluster != normalized[j].Cluster {
			return normalized[i].Cluster < normalized[j].Cluster
		}
		return strings.Join(normalized[i].Namespaces, "\x00") < strings.Join(normalized[j].Namespaces, "\x00")
	})
	data, _ := json.Marshal(normalized)
	digest := sha256.Sum256(data)
	return ScopeSnapshot{Rules: normalized, Fingerprint: hex.EncodeToString(digest[:])}
}

func (s ScopeSnapshot) CanRead(cluster, namespace string) bool {
	if namespace == "" {
		namespace = ClusterScopedNamespace
	}
	for _, rule := range s.Rules {
		if rule.Cluster != "*" && rule.Cluster != cluster {
			continue
		}
		for _, allowedNamespace := range rule.Namespaces {
			if allowedNamespace == "*" && namespace != ClusterScopedNamespace {
				return true
			}
			if allowedNamespace == namespace {
				return true
			}
		}
	}
	return false
}

func (s ScopeSnapshot) CanReadCluster(cluster string) bool {
	for _, rule := range s.Rules {
		if rule.Cluster == "*" || rule.Cluster == cluster {
			return len(rule.Namespaces) > 0
		}
	}
	return false
}

func scopeRulesOverlapForCluster(user, source ScopeRule, cluster string) bool {
	if !scopeClusterMatches(user.Cluster, cluster) || !scopeClusterMatches(source.Cluster, cluster) {
		return false
	}
	for _, userNamespace := range user.Namespaces {
		for _, sourceNamespace := range source.Namespaces {
			if namespacesOverlap(userNamespace, sourceNamespace) {
				return true
			}
		}
	}
	return false
}

func scopeClusterMatches(ruleCluster, cluster string) bool {
	return ruleCluster == "*" || ruleCluster == cluster
}

func namespacesOverlap(left, right string) bool {
	if left == right {
		return true
	}
	if left == "*" {
		return right != ClusterScopedNamespace
	}
	if right == "*" {
		return left != ClusterScopedNamespace
	}
	return false
}

func (s ScopeSnapshot) IsUnrestricted() bool {
	return s.Fingerprint == UnrestrictedScope().Fingerprint
}

func ValidateScopeRules(rules []ScopeRule) error {
	for i, rule := range rules {
		if rule.Cluster != strings.TrimSpace(rule.Cluster) {
			return fmt.Errorf("scope rule %d cluster %q contains surrounding whitespace", i, rule.Cluster)
		}
		if strings.TrimSpace(rule.Cluster) == "" {
			return fmt.Errorf("scope rule %d has an empty cluster", i)
		}
		if strings.Contains(rule.Cluster, "*") && rule.Cluster != "*" {
			return fmt.Errorf("scope rule %d has an invalid partial cluster wildcard %q", i, rule.Cluster)
		}
		if len(rule.Namespaces) == 0 {
			return fmt.Errorf("scope rule %d has no namespaces", i)
		}
		for _, namespace := range rule.Namespaces {
			if namespace != strings.TrimSpace(namespace) {
				return fmt.Errorf("scope rule %d namespace %q contains surrounding whitespace", i, namespace)
			}
			if strings.TrimSpace(namespace) == "" {
				return fmt.Errorf("scope rule %d has an empty namespace", i)
			}
			if strings.Contains(namespace, "*") && namespace != "*" {
				return fmt.Errorf("scope rule %d has an invalid partial namespace wildcard %q", i, namespace)
			}
		}
	}
	return nil
}
