package api

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"trivy-ui/auth"
	"trivy-ui/kubernetes"
)

var (
	scanStaleMu    sync.RWMutex
	scanStaleAfter = 72 * time.Hour
)

// ConfigureScanStaleAfter sets after how long without a new scan a report
// counts as stale (SCAN_STALE_AFTER).
func ConfigureScanStaleAfter(age time.Duration) {
	if age <= 0 {
		return
	}
	scanStaleMu.Lock()
	scanStaleAfter = age
	scanStaleMu.Unlock()
}

func currentScanStaleAfter() time.Duration {
	scanStaleMu.RLock()
	defer scanStaleMu.RUnlock()
	return scanStaleAfter
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}

type viewScope struct {
	cluster    string
	namespaces map[string]bool
	access     auth.AccessSnapshot
	resolve    workloadResolverFunc
}

func (h *Handler) parseViewScope(r *http.Request) viewScope {
	scope := viewScope{cluster: r.URL.Query().Get("cluster"), access: requestAuth(r).Access, resolve: registryWorkloadResolver(h.clusterReg)}
	if raw := r.URL.Query().Get("namespace"); raw != "" {
		scope.namespaces = map[string]bool{}
		for _, namespace := range strings.Split(raw, ",") {
			if namespace = strings.TrimSpace(namespace); namespace != "" && namespace != "all" {
				scope.namespaces[namespace] = true
			}
		}
		if len(scope.namespaces) == 0 {
			scope.namespaces = nil
		}
	}
	return scope
}

// vulnerabilityReports returns the current (not retired) vulnerability
// reports the request may see, with their workload.
func (h *Handler) vulnerabilityReports(scope viewScope) ([]Report, []kubernetes.Workload) {
	var reports []Report
	var workloads []kubernetes.Workload
	for _, report := range h.reportSummaries() {
		if reportFamily(report.Type) != familyVulnerabilities {
			continue
		}
		if scope.cluster != "" && report.Cluster != scope.cluster {
			continue
		}
		if scope.namespaces != nil && !scope.namespaces[report.Namespace] {
			continue
		}
		if !scope.access.CanRead(report.Cluster, report.Namespace) {
			continue
		}
		workload := scope.resolve(report)
		if workload.Retired {
			continue
		}
		reports = append(reports, report)
		workloads = append(workloads, workload)
	}
	return reports, workloads
}

type VulnerabilityOccurrence struct {
	Cluster      string `json:"cluster"`
	Namespace    string `json:"namespace"`
	Workload     string `json:"workload"`
	WorkloadKind string `json:"workload_kind,omitempty"`
	Report       string `json:"report"`
	ReportType   string `json:"report_type"`
	Image        string `json:"image,omitempty"`
	Package      string `json:"package"`
	Installed    string `json:"installed"`
	Fixed        string `json:"fixed,omitempty"`
}

type VulnerabilityEntry struct {
	ID          string                    `json:"id"`
	Severity    string                    `json:"severity"`
	Title       string                    `json:"title,omitempty"`
	Fixable     bool                      `json:"fixable"`
	Workloads   int                       `json:"workloads"`
	Images      int                       `json:"images"`
	Packages    []string                  `json:"packages"`
	Occurrences []VulnerabilityOccurrence `json:"occurrences"`
}

// GetVulnerabilities handles GET /api/v1/vulnerabilities: every distinct
// vulnerability with the workloads and images it affects.
func (h *Handler) GetVulnerabilities(w http.ResponseWriter, r *http.Request) {
	scope := h.parseViewScope(r)
	query := r.URL.Query()
	search := strings.ToLower(strings.TrimSpace(query.Get("search")))
	severities := map[string]bool{}
	for _, severity := range strings.Split(strings.ToLower(query.Get("severity")), ",") {
		if severity = strings.TrimSpace(severity); severity != "" {
			severities[severity] = true
		}
	}
	onlyFixable := query.Get("fixable") == "true"
	limit := 500
	if raw := query.Get("limit"); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value > 0 {
			limit = value
		}
	}
	if limit > 5000 {
		limit = 5000
	}

	reports, workloads := h.vulnerabilityReports(scope)
	entries := map[string]*VulnerabilityEntry{}
	workloadSets := map[string]map[string]bool{}
	imageSets := map[string]map[string]bool{}
	indexed := len(reports) == 0
	for i, report := range reports {
		findings, ok := reportFindings(report)
		if !ok {
			continue
		}
		indexed = true
		image, _ := reportImage(report)
		workload := workloads[i]
		for _, raw := range findings {
			finding, ok := raw.([]interface{})
			if !ok {
				continue
			}
			id := findingField(finding, kubernetes.FindingID)
			severity := findingField(finding, kubernetes.FindingSeverity)
			entry := entries[id]
			if entry == nil {
				entry = &VulnerabilityEntry{ID: id, Severity: severity, Title: findingField(finding, kubernetes.FindingTitle)}
				entries[id] = entry
				workloadSets[id] = map[string]bool{}
				imageSets[id] = map[string]bool{}
			}
			if severityRank[severity] < severityRank[entry.Severity] {
				entry.Severity = severity
			}
			occurrence := VulnerabilityOccurrence{
				Cluster: report.Cluster, Namespace: report.Namespace, Workload: workload.Name, WorkloadKind: workload.Kind,
				Report: report.Name, ReportType: report.Type, Image: image,
				Package:   findingField(finding, kubernetes.FindingPackage),
				Installed: findingField(finding, kubernetes.FindingInstalled),
				Fixed:     findingField(finding, kubernetes.FindingFixed),
			}
			if occurrence.Fixed != "" {
				entry.Fixable = true
			}
			entry.Occurrences = append(entry.Occurrences, occurrence)
			workloadSets[id][report.Cluster+"/"+report.Namespace+"/"+workload.Kind+"/"+workload.Name] = true
			imageSets[id][image] = true
		}
	}

	items := make([]VulnerabilityEntry, 0, len(entries))
	for id, entry := range entries {
		if len(severities) > 0 && !severities[entry.Severity] {
			continue
		}
		if onlyFixable && !entry.Fixable {
			continue
		}
		packages := map[string]bool{}
		for _, occurrence := range entry.Occurrences {
			packages[occurrence.Package] = true
		}
		for name := range packages {
			entry.Packages = append(entry.Packages, name)
		}
		sort.Strings(entry.Packages)
		if search != "" && !vulnerabilityMatches(entry, search) {
			continue
		}
		entry.Workloads = len(workloadSets[id])
		entry.Images = len(imageSets[id])
		sort.Slice(entry.Occurrences, func(i, j int) bool {
			a, b := entry.Occurrences[i], entry.Occurrences[j]
			return a.Cluster+"/"+a.Namespace+"/"+a.Workload+"/"+a.Package < b.Cluster+"/"+b.Namespace+"/"+b.Workload+"/"+b.Package
		})
		items = append(items, *entry)
	}
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] < severityRank[b.Severity]
		}
		if a.Fixable != b.Fixable {
			return a.Fixable
		}
		if a.Workloads != b.Workloads {
			return a.Workloads > b.Workloads
		}
		return a.ID < b.ID
	})
	total := len(items)
	truncated := total > limit
	if truncated {
		items = items[:limit]
	}
	writeJSON(w, http.StatusOK, Response{Code: CodeSuccess, Message: "Success", Data: map[string]interface{}{
		"total": total, "truncated": truncated, "indexed": indexed, "items": items,
	}})
}

func vulnerabilityMatches(entry *VulnerabilityEntry, search string) bool {
	if strings.Contains(strings.ToLower(entry.ID), search) || strings.Contains(strings.ToLower(entry.Title), search) {
		return true
	}
	for _, name := range entry.Packages {
		if strings.Contains(strings.ToLower(name), search) {
			return true
		}
	}
	for _, occurrence := range entry.Occurrences {
		if strings.Contains(strings.ToLower(occurrence.Workload), search) || strings.Contains(strings.ToLower(occurrence.Image), search) ||
			strings.Contains(strings.ToLower(occurrence.Namespace), search) {
			return true
		}
	}
	return false
}

type ImageWorkload struct {
	Cluster   string    `json:"cluster"`
	Namespace string    `json:"namespace"`
	Kind      string    `json:"kind,omitempty"`
	Name      string    `json:"name"`
	Report    ReportRef `json:"report"`
}

type ImageEntry struct {
	Image           string          `json:"image"`
	Digest          string          `json:"digest,omitempty"`
	Critical        int             `json:"critical"`
	High            int             `json:"high"`
	Medium          int             `json:"medium"`
	Low             int             `json:"low"`
	Unknown         int             `json:"unknown"`
	FixableCritical int             `json:"fixable_critical"`
	FixableHigh     int             `json:"fixable_high"`
	Workloads       []ImageWorkload `json:"workloads"`
	Reports         []ReportRef     `json:"reports"`
	ScannedAt       *time.Time      `json:"scanned_at,omitempty"`
}

// GetImages handles GET /api/v1/images: vulnerability counts per image, once
// per image however many workloads run it.
func (h *Handler) GetImages(w http.ResponseWriter, r *http.Request) {
	scope := h.parseViewScope(r)
	search := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("search")))
	reports, workloads := h.vulnerabilityReports(scope)
	entries := map[string]*ImageEntry{}
	seenWorkloads := map[string]map[string]bool{}
	for i, report := range reports {
		image, digest := reportImage(report)
		if image == "" {
			continue
		}
		key := image + "@" + digest
		entry := entries[key]
		if entry == nil {
			counts := countReport(report)
			entry = &ImageEntry{Image: image, Digest: digest,
				Critical: counts.critical, High: counts.high, Medium: counts.medium, Low: counts.low, Unknown: counts.unknown,
				FixableCritical: counts.fixableCritical, FixableHigh: counts.fixableHigh}
			entries[key] = entry
			seenWorkloads[key] = map[string]bool{}
		}
		ref := ReportRef{Cluster: report.Cluster, Namespace: report.Namespace, Type: report.Type, Name: report.Name}
		entry.Reports = append(entry.Reports, ref)
		if scanned, ok := reportScannedAt(report); ok && (entry.ScannedAt == nil || scanned.Before(*entry.ScannedAt)) {
			entry.ScannedAt = &scanned
		}
		workload := workloads[i]
		workloadKey := report.Cluster + "/" + report.Namespace + "/" + workload.Kind + "/" + workload.Name
		if !seenWorkloads[key][workloadKey] {
			seenWorkloads[key][workloadKey] = true
			entry.Workloads = append(entry.Workloads, ImageWorkload{Cluster: report.Cluster, Namespace: report.Namespace, Kind: workload.Kind, Name: workload.Name, Report: ref})
		}
	}
	items := make([]ImageEntry, 0, len(entries))
	for _, entry := range entries {
		if search != "" && !imageMatches(entry, search) {
			continue
		}
		items = append(items, *entry)
	}
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		left := [5]int{a.Critical, a.High, a.Medium, a.Low, a.Unknown}
		right := [5]int{b.Critical, b.High, b.Medium, b.Low, b.Unknown}
		for k := range left {
			if left[k] != right[k] {
				return left[k] > right[k]
			}
		}
		return a.Image < b.Image
	})
	writeJSON(w, http.StatusOK, Response{Code: CodeSuccess, Message: "Success", Data: map[string]interface{}{
		"total": len(items), "items": items,
	}})
}

func imageMatches(entry *ImageEntry, search string) bool {
	if strings.Contains(strings.ToLower(entry.Image), search) {
		return true
	}
	for _, workload := range entry.Workloads {
		if strings.Contains(strings.ToLower(workload.Name), search) || strings.Contains(strings.ToLower(workload.Namespace), search) {
			return true
		}
	}
	return false
}
