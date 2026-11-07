package api

import "time"

// Accessors for the untyped report data (map[string]interface{}) kept in
// the cache. Everything that reads summaries goes through these helpers.

type reportCounts struct {
	critical, high, medium, low, unknown                                    int
	fixableCritical, fixableHigh, fixableMedium, fixableLow, fixableUnknown int
	compliancePass, complianceFail                                          int
	hasCompliance                                                           bool
}

func reportData(report Report) map[string]interface{} {
	data, _ := report.Data.(map[string]interface{})
	return data
}

func countReport(report Report) reportCounts {
	var counts reportCounts
	data := reportData(report)
	if data == nil {
		return counts
	}
	var summary map[string]interface{}
	if body, ok := data["report"].(map[string]interface{}); ok {
		summary, _ = body["summary"].(map[string]interface{})
	}
	if summary == nil {
		summary, _ = data["summary"].(map[string]interface{})
	}
	if summary != nil {
		counts.critical = intValue(summary["criticalCount"])
		counts.high = intValue(summary["highCount"])
		counts.medium = intValue(summary["mediumCount"])
		counts.low = intValue(summary["lowCount"])
		counts.unknown = intValue(summary["unknownCount"])
	}
	if derived, ok := data["derived"].(map[string]interface{}); ok {
		if fixable, ok := derived["fixable"].(map[string]interface{}); ok {
			counts.fixableCritical = intValue(fixable["critical"])
			counts.fixableHigh = intValue(fixable["high"])
			counts.fixableMedium = intValue(fixable["medium"])
			counts.fixableLow = intValue(fixable["low"])
			counts.fixableUnknown = intValue(fixable["unknown"])
		}
		if compliance, ok := derived["compliance"].(map[string]interface{}); ok {
			counts.hasCompliance = true
			counts.compliancePass = intValue(compliance["pass"])
			counts.complianceFail = intValue(compliance["fail"])
		}
	}
	return counts
}

func intValue(value interface{}) int {
	switch number := value.(type) {
	case float64:
		return int(number)
	case int:
		return number
	case int64:
		return int(number)
	case uint64:
		return int(number)
	}
	return 0
}

// derivedVersion tells whether a cached summary already carries the derived
// counts of the current version.
func derivedVersion(report Report) int {
	if data := reportData(report); data != nil {
		if derived, ok := data["derived"].(map[string]interface{}); ok {
			return intValue(derived["version"])
		}
	}
	return 0
}

func reportLabels(report Report) map[string]string {
	labels := map[string]string{}
	data := reportData(report)
	if data == nil {
		return labels
	}
	metadata, _ := data["metadata"].(map[string]interface{})
	raw, _ := metadata["labels"].(map[string]interface{})
	for key, value := range raw {
		if text, ok := value.(string); ok {
			labels[key] = text
		}
	}
	if typed, ok := metadata["labels"].(map[string]string); ok {
		for key, value := range typed {
			labels[key] = value
		}
	}
	return labels
}

// reportScannedAt is the report's updateTimestamp (when the operator scanned).
func reportScannedAt(report Report) (time.Time, bool) {
	data := reportData(report)
	if data == nil {
		return time.Time{}, false
	}
	for _, key := range []string{"report", "status"} {
		if body, ok := data[key].(map[string]interface{}); ok {
			if raw, ok := body["updateTimestamp"].(string); ok {
				if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
					return parsed, true
				}
			}
		}
	}
	return time.Time{}, false
}

// withoutFindings returns report data without derived.findings, which only
// the CVE and image views need.
func withoutFindings(data interface{}) interface{} {
	source, ok := data.(map[string]interface{})
	if !ok {
		return data
	}
	derived, ok := source["derived"].(map[string]interface{})
	if !ok {
		return data
	}
	if _, has := derived["findings"]; !has {
		return data
	}
	copied := make(map[string]interface{}, len(source))
	for key, value := range source {
		copied[key] = value
	}
	slim := make(map[string]interface{}, len(derived))
	for key, value := range derived {
		if key != "findings" {
			slim[key] = value
		}
	}
	copied["derived"] = slim
	return copied
}

func reportImage(report Report) (image, digest string) {
	data := reportData(report)
	body, _ := data["report"].(map[string]interface{})
	artifact, _ := body["artifact"].(map[string]interface{})
	registry, _ := body["registry"].(map[string]interface{})
	repository, _ := artifact["repository"].(string)
	tag, _ := artifact["tag"].(string)
	digest, _ = artifact["digest"].(string)
	server, _ := registry["server"].(string)
	if repository == "" {
		return "", digest
	}
	image = repository
	if server != "" {
		image = server + "/" + repository
	}
	if tag != "" {
		image += ":" + tag
	}
	return image, digest
}

func reportFindings(report Report) ([]interface{}, bool) {
	data := reportData(report)
	derived, _ := data["derived"].(map[string]interface{})
	findings, ok := derived["findings"].([]interface{})
	return findings, ok
}

func findingField(finding []interface{}, index int) string {
	if index < len(finding) {
		text, _ := finding[index].(string)
		return text
	}
	return ""
}

// hasVulnerabilitiesInReport reports Critical, High, Medium or Low findings
// (UNKNOWN does not count, as before); it drives the "Issues only" filter.
func hasVulnerabilitiesInReport(report Report) bool {
	counts := countReport(report)
	return counts.critical+counts.high+counts.medium+counts.low > 0
}

// extractSummaryCounts returns the Critical, High, Medium and Low counts.
func extractSummaryCounts(report Report) (int, int, int, int) {
	counts := countReport(report)
	return counts.critical, counts.high, counts.medium, counts.low
}
