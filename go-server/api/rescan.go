package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"trivy-ui/auth"
	"trivy-ui/config"
	"trivy-ui/utils"
)

// Rescan: the Trivy Operator scans a workload again when its report is
// deleted. A rescan therefore deletes the report and keeps showing the last
// result, marked as rescanning, until the operator writes the new one.

var defaultRescanTypes = []string{
	"vulnerabilityreports",
	"exposedsecretreports",
	"sbomreports",
	"configauditreports",
	"rbacassessmentreports",
	"infraassessmentreports",
	"clusterconfigauditreports",
	"clusterrbacassessmentreports",
	"clusterinfraassessmentreports",
}

type RescanConfig struct {
	Enabled        bool
	Groups         []string
	Types          []string
	Timeout        time.Duration
	MaxBulk        int
	MaxPending     int
	AllowedOrigins []string
}

func (c RescanConfig) typeAllowed(typeName string) bool {
	for _, allowed := range c.Types {
		if allowed == typeName {
			return true
		}
	}
	return false
}

func RescanConfigFromEnv() (RescanConfig, error) {
	cfg := RescanConfig{Types: defaultRescanTypes, Timeout: 6 * time.Hour, MaxBulk: 50, MaxPending: 100}
	var err error
	if raw := os.Getenv("ENABLE_RESCAN"); raw != "" {
		if cfg.Enabled, err = strconv.ParseBool(raw); err != nil {
			return cfg, fmt.Errorf("parse ENABLE_RESCAN: %w", err)
		}
	}
	cfg.Groups = splitList(os.Getenv("RESCAN_GROUPS"))
	if types := splitList(os.Getenv("RESCAN_TYPES")); len(types) > 0 {
		for i := range types {
			types[i] = strings.ToLower(types[i])
		}
		cfg.Types = types
	}
	if raw := os.Getenv("RESCAN_TIMEOUT"); raw != "" {
		if cfg.Timeout, err = time.ParseDuration(raw); err != nil || cfg.Timeout <= 0 {
			return cfg, fmt.Errorf("parse RESCAN_TIMEOUT: invalid duration %q", raw)
		}
	}
	for env, target := range map[string]*int{"RESCAN_MAX_BULK": &cfg.MaxBulk, "RESCAN_MAX_PENDING": &cfg.MaxPending} {
		if raw := os.Getenv(env); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value <= 0 {
				return cfg, fmt.Errorf("parse %s: must be a positive integer", env)
			}
			*target = value
		}
	}
	for _, origin := range splitList(os.Getenv("CORS_ALLOWED_ORIGINS")) {
		if origin != "*" {
			cfg.AllowedOrigins = append(cfg.AllowedOrigins, origin)
		}
	}
	return cfg, nil
}

func splitList(raw string) []string {
	var values []string
	for _, value := range strings.Split(raw, ",") {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}
	return values
}

var (
	rescanConfigMu sync.RWMutex
	rescanConfig   = RescanConfig{Types: defaultRescanTypes, Timeout: 6 * time.Hour, MaxBulk: 50, MaxPending: 100}
	rescans        = newRescanTracker()
)

// ConfigureRescan sets the rescan configuration for all handlers.
func ConfigureRescan(cfg RescanConfig) {
	rescanConfigMu.Lock()
	rescanConfig = cfg
	rescanConfigMu.Unlock()
}

func currentRescanConfig() RescanConfig {
	rescanConfigMu.RLock()
	defer rescanConfigMu.RUnlock()
	return rescanConfig
}

type RescanState struct {
	RequestedAt time.Time `json:"requestedAt"`
	RequestedBy string    `json:"requestedBy"`
}

type pendingRescan struct {
	ref             ReportRef
	state           RescanState
	resourceVersion string
	summary         Report
	detail          *Report
}

type rescanTracker struct {
	mu        sync.Mutex
	pending   map[string]*pendingRescan
	sweepOnce sync.Once
	bulkMu    sync.Mutex
}

func newRescanTracker() *rescanTracker {
	return &rescanTracker{pending: make(map[string]*pendingRescan)}
}

func (t *rescanTracker) begin(key string, p *pendingRescan) bool {
	t.sweepOnce.Do(func() { go t.sweepLoop() })
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, exists := t.pending[key]; exists {
		return false
	}
	t.pending[key] = p
	return true
}

func (t *rescanTracker) cancel(key string) {
	t.mu.Lock()
	delete(t.pending, key)
	t.mu.Unlock()
}

// holds reports whether a report's cache entry must survive its deletion in
// Kubernetes because a rescan is waiting for its replacement.
func (t *rescanTracker) holds(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.pending[key]
	return ok
}

// observe ends a pending rescan once a report with a new resourceVersion
// arrives under the same name.
func (t *rescanTracker) observe(key, resourceVersion string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p, ok := t.pending[key]; ok && resourceVersion != p.resourceVersion {
		delete(t.pending, key)
		utils.LogInfo("rescan_completed", map[string]interface{}{
			"cluster": p.ref.Cluster, "namespace": p.ref.Namespace, "type": p.ref.Type, "name": p.ref.Name,
			"requested_by": p.state.RequestedBy, "duration": time.Since(p.state.RequestedAt).Round(time.Second).String(),
		})
	}
}

func (t *rescanTracker) status(key string) *RescanState {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p, ok := t.pending[key]; ok {
		state := p.state
		return &state
	}
	return nil
}

func (t *rescanTracker) heldReport(key string) (Report, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.pending[key]
	if !ok {
		return Report{}, false
	}
	report := p.summary
	if p.detail != nil {
		report = *p.detail
	}
	state := p.state
	report.Rescan = &state
	return report, true
}

func (t *rescanTracker) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.pending)
}

func (t *rescanTracker) list() []pendingRescan {
	t.mu.Lock()
	defer t.mu.Unlock()
	items := make([]pendingRescan, 0, len(t.pending))
	for _, p := range t.pending {
		items = append(items, *p)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].state.RequestedAt.Before(items[j].state.RequestedAt) })
	return items
}

// expire drops rescans whose report never came back (workload gone, scan
// failed) and removes their cached results.
func (t *rescanTracker) expire(now time.Time, timeout time.Duration) []ReportRef {
	t.mu.Lock()
	var expired []ReportRef
	for key, p := range t.pending {
		if now.Sub(p.state.RequestedAt) > timeout {
			expired = append(expired, p.ref)
			delete(t.pending, key)
		}
	}
	t.mu.Unlock()
	if cache := getCache(); cache != nil {
		for _, ref := range expired {
			utils.LogWarning("rescan_timed_out", map[string]interface{}{"cluster": ref.Cluster, "namespace": ref.Namespace, "type": ref.Type, "name": ref.Name})
			cache.DeleteReportEntry(ref.Cluster, ref.Namespace, ref.Type, ref.Name)
		}
	}
	return expired
}

func (t *rescanTracker) sweepLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for now := range ticker.C {
		t.expire(now, currentRescanConfig().Timeout)
	}
}

func canRescan(cfg RescanConfig, h *Handler, principal auth.Principal) bool {
	if !cfg.Enabled || h.auth == nil || !h.auth.IsEnabled() {
		return false
	}
	if len(cfg.Groups) == 0 {
		return true
	}
	for _, group := range principal.Groups {
		for _, allowed := range cfg.Groups {
			if group == allowed {
				return true
			}
		}
	}
	return false
}

// sameOriginRequest rejects state-changing requests sent by a browser from
// another site. Non-browser clients send neither header and are allowed.
func sameOriginRequest(r *http.Request, allowedOrigins []string) bool {
	origin := r.Header.Get("Origin")
	// Origins configured for credentialed CORS are trusted even though the
	// browser marks their requests cross-site.
	for _, allowed := range allowedOrigins {
		if origin != "" && origin == allowed {
			return true
		}
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host)
}

// authorizeRescan writes the error response and returns false when the
// request may not trigger rescans.
func (h *Handler) authorizeRescan(w http.ResponseWriter, r *http.Request, cfg RescanConfig) bool {
	if !cfg.Enabled {
		writeError(w, r, http.StatusForbidden, ErrRescanDisabled, "rescanning is disabled (ENABLE_RESCAN)")
		return false
	}
	if !sameOriginRequest(r, cfg.AllowedOrigins) {
		writeError(w, r, http.StatusForbidden, ErrAccessDenied, "cross-origin request rejected")
		return false
	}
	if !canRescan(cfg, h, requestAuth(r).Principal) {
		writeError(w, r, http.StatusForbidden, ErrAccessDenied, "not allowed to request rescans")
		return false
	}
	return true
}

type rescanOutcome int

const (
	rescanAccepted rescanOutcome = iota
	rescanAlreadyPending
	rescanConflict
	rescanFailed
)

func (h *Handler) requestRescan(ctx context.Context, r *http.Request, kind config.ReportKind, summary Report) (rescanOutcome, *RescanState) {
	key := reportKey(summary.Cluster, summary.Namespace, summary.Type, summary.Name)
	clusterClient := h.clusterReg.Get(summary.Cluster)
	if clusterClient == nil || clusterClient.Client == nil {
		return rescanFailed, nil
	}
	user := requestAuth(r).Principal.Username
	pending := &pendingRescan{
		ref:             ReportRef{Cluster: summary.Cluster, Namespace: summary.Namespace, Type: summary.Type, Name: summary.Name},
		state:           RescanState{RequestedAt: time.Now().UTC(), RequestedBy: user},
		resourceVersion: summary.ResourceVersion,
		summary:         summary,
	}
	// Keep an already cached full result so the detail view still works while
	// the report does not exist in Kubernetes. Nothing is fetched for this:
	// the tracker must not hold large reports outside the bounded detail cache.
	if detail, found := GetReportDetail(summary.Cluster, summary.Namespace, summary.Type, summary.Name); found && detail.ResourceVersion == summary.ResourceVersion {
		pending.detail = &detail
	}
	if !rescans.begin(key, pending) {
		return rescanAlreadyPending, rescans.status(key)
	}
	err := clusterClient.Client.DeleteReport(ctx, kind, summary.Namespace, summary.Name, reportUID(summary))
	logFields := map[string]interface{}{
		"user": user, "src_ip": getClientIP(r), "cluster": summary.Cluster,
		"namespace": summary.Namespace, "type": summary.Type, "name": summary.Name,
	}
	switch {
	case err == nil || apierrors.IsNotFound(err):
		utils.LogInfo("rescan_requested", logFields)
		return rescanAccepted, &pending.state
	case apierrors.IsConflict(err):
		rescans.cancel(key)
		return rescanConflict, nil
	default:
		rescans.cancel(key)
		logFields["error"] = err.Error()
		utils.LogWarning("rescan_failed", logFields)
		return rescanFailed, nil
	}
}

func reportUID(report Report) string {
	if data, ok := report.Data.(map[string]interface{}); ok {
		if metadata, ok := data["metadata"].(map[string]interface{}); ok {
			if uid, ok := metadata["uid"].(string); ok {
				return uid
			}
		}
	}
	return ""
}

func reportUpdatedAt(report Report) (time.Time, bool) {
	if data, ok := report.Data.(map[string]interface{}); ok {
		if body, ok := data["report"].(map[string]interface{}); ok {
			if raw, ok := body["updateTimestamp"].(string); ok {
				if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
					return parsed, true
				}
			}
		}
	}
	return time.Time{}, false
}

// RescanReport handles POST /api/v1/reports/{cluster}/{type}/{namespace}/{name}/rescan.
func (h *Handler) RescanReport(w http.ResponseWriter, r *http.Request, cluster, typeName, namespace, name string) {
	cfg := currentRescanConfig()
	if !h.authorizeRescan(w, r, cfg) {
		return
	}
	typeName = strings.ToLower(typeName)
	if !cfg.typeAllowed(typeName) {
		writeError(w, r, http.StatusBadRequest, ErrValidationFailed, "this report type cannot be rescanned")
		return
	}
	kind := h.reportRegistry(cluster).GetReportByName(typeName)
	if kind == nil {
		writeError(w, r, http.StatusBadRequest, ErrValidationFailed, "Invalid report type")
		return
	}
	if !kind.Namespaced {
		namespace = ""
	}
	if !requestAuth(r).Access.CanRead(cluster, namespace) {
		writeError(w, r, http.StatusForbidden, ErrAccessDenied, "report access denied")
		return
	}
	key := reportKey(cluster, namespace, typeName, name)
	if state := rescans.status(key); state != nil {
		writeJSON(w, http.StatusAccepted, Response{Code: CodeSuccess, Message: "Rescan already in progress", Data: map[string]interface{}{"rescan": state}})
		return
	}
	cache := getCache()
	if cache == nil {
		writeError(w, r, http.StatusServiceUnavailable, ErrProviderUnavailable, "cache unavailable")
		return
	}
	value, found := cache.Get(key)
	summary, ok := decodeReportValue(value)
	if !found || !ok {
		writeError(w, r, http.StatusNotFound, ErrReportNotFound, "Report not found")
		return
	}
	if rescans.count() >= cfg.MaxPending {
		writeError(w, r, http.StatusTooManyRequests, ErrRescanLimit, fmt.Sprintf("too many rescans in progress (limit %d)", cfg.MaxPending))
		return
	}
	outcome, state := h.requestRescan(r.Context(), r, *kind, summary)
	switch outcome {
	case rescanAccepted, rescanAlreadyPending:
		writeJSON(w, http.StatusAccepted, Response{Code: CodeSuccess, Message: "Rescan requested", Data: map[string]interface{}{"rescan": state}})
	case rescanConflict:
		writeError(w, r, http.StatusConflict, ErrConflict, "the report changed in the meantime; reload and try again")
	default:
		writeError(w, r, http.StatusServiceUnavailable, ErrProviderUnavailable, "could not delete the report to trigger a rescan")
	}
}

type bulkRescanRequest struct {
	Cluster    string   `json:"cluster"`
	Namespaces []string `json:"namespaces"`
	Types      []string `json:"types"`
	OlderThan  string   `json:"olderThan"`
	DryRun     bool     `json:"dryRun"`
}

type bulkRescanFailure struct {
	Ref    ReportRef `json:"ref"`
	Reason string    `json:"reason"`
}

// RescanBulk handles POST /api/v1/rescan: rescan every matching report of a
// cluster, optionally limited to namespaces, report types and reports older
// than a duration. dryRun only counts.
func (h *Handler) RescanBulk(w http.ResponseWriter, r *http.Request) {
	cfg := currentRescanConfig()
	if !h.authorizeRescan(w, r, cfg) {
		return
	}
	var request bulkRescanRequest
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, r, http.StatusBadRequest, ErrValidationFailed, "invalid request body")
		return
	}
	if request.Cluster == "" {
		writeError(w, r, http.StatusBadRequest, ErrValidationFailed, "cluster is required")
		return
	}
	access := requestAuth(r).Access
	if !access.CanReadCluster(request.Cluster) {
		writeError(w, r, http.StatusForbidden, ErrAccessDenied, "cluster access denied")
		return
	}
	types := map[string]bool{}
	if len(request.Types) == 0 {
		for _, typeName := range cfg.Types {
			types[typeName] = true
		}
	}
	for _, typeName := range request.Types {
		typeName = strings.ToLower(strings.TrimSpace(typeName))
		if !cfg.typeAllowed(typeName) {
			writeError(w, r, http.StatusBadRequest, ErrValidationFailed, fmt.Sprintf("report type %q cannot be rescanned", typeName))
			return
		}
		types[typeName] = true
	}
	namespaces := map[string]bool{}
	for _, namespace := range request.Namespaces {
		if namespace == auth.ClusterScopedNamespace {
			namespace = ""
		}
		namespaces[namespace] = true
	}
	var cutoff time.Time
	if request.OlderThan != "" {
		age, err := time.ParseDuration(request.OlderThan)
		if err != nil || age <= 0 {
			writeError(w, r, http.StatusBadRequest, ErrValidationFailed, "olderThan must be a positive duration such as 12h")
			return
		}
		cutoff = time.Now().Add(-age)
	}

	cache := getCache()
	if cache == nil {
		writeError(w, r, http.StatusServiceUnavailable, ErrProviderUnavailable, "cache unavailable")
		return
	}
	registry := h.reportRegistry(request.Cluster)
	var matches []Report
	for _, report := range cache.ReportSummaries() {
		if report.Cluster != request.Cluster || !types[report.Type] {
			continue
		}
		if len(namespaces) > 0 && !namespaces[report.Namespace] {
			continue
		}
		if !access.CanRead(report.Cluster, report.Namespace) || registry.GetReportByName(report.Type) == nil {
			continue
		}
		if rescans.holds(reportKey(report.Cluster, report.Namespace, report.Type, report.Name)) {
			continue
		}
		if !cutoff.IsZero() {
			if updated, ok := reportUpdatedAt(report); ok && updated.After(cutoff) {
				continue
			}
		}
		matches = append(matches, report)
	}
	sort.Slice(matches, func(i, j int) bool {
		return reportKey(matches[i].Cluster, matches[i].Namespace, matches[i].Type, matches[i].Name) <
			reportKey(matches[j].Cluster, matches[j].Namespace, matches[j].Type, matches[j].Name)
	})
	refs := make([]ReportRef, 0, len(matches))
	for _, report := range matches {
		refs = append(refs, ReportRef{Cluster: report.Cluster, Namespace: report.Namespace, Type: report.Type, Name: report.Name})
	}

	if request.DryRun || len(matches) == 0 {
		writeJSON(w, http.StatusOK, Response{Code: CodeSuccess, Message: "Success", Data: map[string]interface{}{
			"count": len(matches), "maxBulk": cfg.MaxBulk, "reports": refs,
		}})
		return
	}
	if len(matches) > cfg.MaxBulk {
		writeError(w, r, http.StatusBadRequest, ErrRescanLimit, fmt.Sprintf("%d reports match; at most %d can be rescanned at once — narrow the selection", len(matches), cfg.MaxBulk))
		return
	}
	if rescans.count()+len(matches) > cfg.MaxPending {
		writeError(w, r, http.StatusTooManyRequests, ErrRescanLimit, fmt.Sprintf("too many rescans in progress (limit %d)", cfg.MaxPending))
		return
	}
	if !rescans.bulkMu.TryLock() {
		writeError(w, r, http.StatusTooManyRequests, ErrRescanLimit, "another bulk rescan is being submitted")
		return
	}
	defer rescans.bulkMu.Unlock()

	accepted := 0
	var failures []bulkRescanFailure
	for i, report := range matches {
		outcome, _ := h.requestRescan(r.Context(), r, *registry.GetReportByName(report.Type), report)
		switch outcome {
		case rescanAccepted, rescanAlreadyPending:
			accepted++
		case rescanConflict:
			failures = append(failures, bulkRescanFailure{Ref: refs[i], Reason: "changed in the meantime"})
		default:
			failures = append(failures, bulkRescanFailure{Ref: refs[i], Reason: "delete failed"})
		}
	}
	utils.LogInfo("rescan_bulk_requested", map[string]interface{}{
		"user": requestAuth(r).Principal.Username, "src_ip": getClientIP(r), "cluster": request.Cluster,
		"namespaces": request.Namespaces, "types": request.Types, "older_than": request.OlderThan,
		"matched": len(matches), "accepted": accepted, "failed": len(failures),
	})
	writeJSON(w, http.StatusAccepted, Response{Code: CodeSuccess, Message: "Rescan requested", Data: map[string]interface{}{
		"count": len(matches), "accepted": accepted, "failed": failures,
	}})
}

type pendingRescanView struct {
	Ref         ReportRef `json:"ref"`
	RequestedAt time.Time `json:"requestedAt"`
	RequestedBy string    `json:"requestedBy"`
}

// RescanStatus handles GET /api/v1/rescan: what the current user may do and
// which rescans are in progress.
func (h *Handler) RescanStatus(w http.ResponseWriter, r *http.Request) {
	cfg := currentRescanConfig()
	access := requestAuth(r).Access
	pending := make([]pendingRescanView, 0)
	for _, p := range rescans.list() {
		if access.CanRead(p.ref.Cluster, p.ref.Namespace) {
			pending = append(pending, pendingRescanView{Ref: p.ref, RequestedAt: p.state.RequestedAt, RequestedBy: p.state.RequestedBy})
		}
	}
	writeJSON(w, http.StatusOK, Response{Code: CodeSuccess, Message: "Success", Data: map[string]interface{}{
		"enabled": cfg.Enabled,
		"allowed": canRescan(cfg, h, requestAuth(r).Principal),
		"types":   cfg.Types,
		"maxBulk": cfg.MaxBulk,
		"pending": pending,
	}})
}

// withRescanState marks reports whose rescan is still in progress.
func withRescanState(reports []Report) []Report {
	if rescans.count() == 0 {
		return reports
	}
	decorated := make([]Report, len(reports))
	for i, report := range reports {
		report.Rescan = rescans.status(reportKey(report.Cluster, report.Namespace, report.Type, report.Name))
		decorated[i] = report
	}
	return decorated
}
