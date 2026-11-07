package kubernetes

import "strings"

// DerivedVersion is bumped whenever the derived summary changes shape, so
// cached summaries from an older version are replaced on the next sync.
const DerivedVersion = 1

var severityKeys = []string{"critical", "high", "medium", "low", "unknown"}

// deriveSummary computes numbers the operator's summary does not have, while
// the full report is still available (the informer drops the large lists
// afterwards):
//
//   - vulnerability reports: findings with a fixed version ("fixable") and
//     distinct vulnerability IDs, per severity;
//   - compliance reports: pass/fail counts from status.summary.
func deriveSummary(obj map[string]interface{}) map[string]interface{} {
	derived := map[string]interface{}{"version": DerivedVersion}
	if body, ok := obj["report"].(map[string]interface{}); ok {
		if vulnerabilities, ok := body["vulnerabilities"].([]interface{}); ok {
			fixable := zeroSeverityCounts()
			unique := make(map[string]map[string]struct{}, len(severityKeys))
			for _, key := range severityKeys {
				unique[key] = make(map[string]struct{})
			}
			for _, item := range vulnerabilities {
				vulnerability, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				severity := severityKey(vulnerability["severity"])
				if fixed, _ := vulnerability["fixedVersion"].(string); strings.TrimSpace(fixed) != "" {
					fixable[severity]++
				}
				if id, _ := vulnerability["vulnerabilityID"].(string); id != "" {
					unique[severity][id] = struct{}{}
				}
			}
			uniqueCounts := zeroSeverityCounts()
			for key, ids := range unique {
				uniqueCounts[key] = len(ids)
			}
			derived["fixable"] = toInterfaceMap(fixable)
			derived["unique"] = toInterfaceMap(uniqueCounts)
		}
	}
	if status, ok := obj["status"].(map[string]interface{}); ok {
		if summary, ok := status["summary"].(map[string]interface{}); ok {
			derived["compliance"] = map[string]interface{}{
				"pass": numberValue(summary["passCount"]),
				"fail": numberValue(summary["failCount"]),
			}
		}
	}
	return derived
}

func severityKey(value interface{}) string {
	severity, _ := value.(string)
	switch key := strings.ToLower(strings.TrimSpace(severity)); key {
	case "critical", "high", "medium", "low":
		return key
	default:
		return "unknown"
	}
}

func zeroSeverityCounts() map[string]int {
	counts := make(map[string]int, len(severityKeys))
	for _, key := range severityKeys {
		counts[key] = 0
	}
	return counts
}

func toInterfaceMap(counts map[string]int) map[string]interface{} {
	result := make(map[string]interface{}, len(counts))
	for key, value := range counts {
		result[key] = value
	}
	return result
}

func numberValue(value interface{}) int {
	switch number := value.(type) {
	case float64:
		return int(number)
	case int:
		return number
	case int64:
		return int(number)
	}
	return 0
}
