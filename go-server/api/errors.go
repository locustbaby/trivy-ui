package api

import (
	"net/http"
	"trivy-ui/utils"
)

// ErrorCode is a stable machine-readable error identifier returned in the
// APIError.Type field of every error response. Frontends branch on these
// values, so existing codes must never be renamed or reused with different
// semantics; add new codes instead.
type ErrorCode string

const (
	ErrInternalError       ErrorCode = "INTERNAL_ERROR"
	ErrValidationFailed    ErrorCode = "VALIDATION_FAILED"
	ErrAuthRequired        ErrorCode = "AUTH_REQUIRED"
	ErrAccessDenied        ErrorCode = "ACCESS_DENIED"
	ErrReportNotFound      ErrorCode = "REPORT_NOT_FOUND"
	ErrReportAmbiguous     ErrorCode = "REPORT_AMBIGUOUS"
	ErrProviderUnavailable ErrorCode = "PROVIDER_UNAVAILABLE"
	ErrDataIncomplete      ErrorCode = "DATA_INCOMPLETE"
)

// writeError emits the canonical JSON error envelope and logs the failure
// with the request ID so application errors can be correlated with the
// access log. The error code is always explicit at the call site; there is
// intentionally no inference from message text.
//
// Logging policy: 5xx failures are logged at error level, authentication and
// authorization denials at warning level (audit value), everything else at
// debug level to avoid noise from routine client mistakes.
func writeError(w http.ResponseWriter, r *http.Request, status int, code ErrorCode, message string) {
	logFields := map[string]interface{}{
		"request_id": w.Header().Get("X-Request-ID"),
		"code":       string(code),
		"status":     status,
		"message":    message,
	}
	if r != nil {
		logFields["method"] = r.Method
		logFields["path"] = r.URL.Path
		if clientIP := getClientIP(r); clientIP != "" {
			logFields["src_ip"] = clientIP
		}
	}
	switch {
	case status >= http.StatusInternalServerError:
		utils.LogError("api_error", logFields)
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		utils.LogWarning("api_error", logFields)
	default:
		utils.LogDebug("api_error", logFields)
	}

	writeJSON(w, status, Response{
		Code:    CodeError,
		Message: message,
		Error:   &APIError{Type: string(code), RequestID: w.Header().Get("X-Request-ID")},
	})
}
