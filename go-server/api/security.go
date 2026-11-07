package api

import (
	"net/http"
	"os"
	"strconv"
	"strings"
)

// DefaultContentSecurityPolicy fits the built dashboard: no inline scripts,
// inline style attributes (charts), same-origin API calls.
const DefaultContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; " +
	"base-uri 'self'; form-action 'self'; frame-ancestors 'none'"

// contentSecurityPolicy returns CONTENT_SECURITY_POLICY, the default when it
// is unset, or "" when it is "off" (e.g. when the UI calls an API on another
// origin and sets its own policy at the proxy).
func contentSecurityPolicy() string {
	value := strings.TrimSpace(os.Getenv("CONTENT_SECURITY_POLICY"))
	switch strings.ToLower(value) {
	case "":
		return DefaultContentSecurityPolicy
	case "off", "none", "false":
		return ""
	}
	return value
}

func envEnabled(name string) bool {
	enabled, err := strconv.ParseBool(os.Getenv(name))
	return err == nil && enabled
}

// SecurityHeaders adds the Content-Security-Policy and isolation headers.
// Swagger UI and the operator-provided error page may use inline scripts and
// are left out of the CSP.
func SecurityHeaders(policy string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("Cross-Origin-Opener-Policy", "same-origin")
		header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if policy != "" && !strings.HasPrefix(r.URL.Path, "/swagger/") && r.URL.Path != "/error-page.html" {
			header.Set("Content-Security-Policy", policy)
		}
		next.ServeHTTP(w, r)
	})
}
