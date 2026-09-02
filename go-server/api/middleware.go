package api

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"trivy-ui/utils"
)

type gzipResponseWriter struct {
	http.ResponseWriter
	gzipWriter    *gzip.Writer
	enabled       bool
	statusWritten bool
}

func (g *gzipResponseWriter) WriteHeader(status int) {
	if g.statusWritten {
		return
	}
	g.statusWritten = true
	if status == http.StatusNoContent || status == http.StatusNotModified || status < 200 {
		g.ResponseWriter.WriteHeader(status)
		return
	}
	g.enabled = true
	g.Header().Del("Content-Length")
	g.Header().Set("Content-Encoding", "gzip")
	g.Header().Add("Vary", "Accept-Encoding")
	g.ResponseWriter.WriteHeader(status)
}

func (g *gzipResponseWriter) Write(data []byte) (int, error) {
	if !g.statusWritten {
		g.WriteHeader(http.StatusOK)
	}
	if !g.enabled {
		return g.ResponseWriter.Write(data)
	}
	return g.gzipWriter.Write(data)
}

type responseWriter struct {
	http.ResponseWriter
	statusCode    int
	size          int
	headerWritten bool
}

type auditContextKey struct{}

type auditContext struct {
	username string
}

func ValidateTrustedProxyCIDRs(raw string) error {
	for _, value := range strings.Split(raw, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(value); err != nil {
			return fmt.Errorf("invalid trusted proxy CIDR %q: %w", value, err)
		}
	}
	return nil
}

func requestCluster(r *http.Request) string {
	if cluster := r.URL.Query().Get("cluster"); cluster != "" {
		return cluster
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	if strings.HasPrefix(path, "clusters/") {
		parts := strings.Split(path, "/")
		if len(parts) > 1 {
			return parts[1]
		}
	}
	if strings.HasPrefix(path, "reports/") {
		parts := strings.Split(path, "/")
		if len(parts) > 1 {
			return parts[1]
		}
	}
	return ""
}

func withAuditContext(r *http.Request) (*http.Request, *auditContext) {
	ctx := &auditContext{username: "anonymous"}
	return r.WithContext(context.WithValue(r.Context(), auditContextKey{}, ctx)), ctx
}

func auditFromRequest(r *http.Request) *auditContext {
	if value, ok := r.Context().Value(auditContextKey{}).(*auditContext); ok {
		return value
	}
	return &auditContext{username: "anonymous"}
}

func requestID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err == nil {
		return hex.EncodeToString(value[:])
	}
	return time.Now().UTC().Format("20060102150405.000000000")
}

func (rw *responseWriter) WriteHeader(code int) {
	if rw.headerWritten {
		return
	}
	rw.statusCode = code
	rw.headerWritten = true
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.headerWritten {
		rw.WriteHeader(http.StatusOK)
	}
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

func getClientIP(r *http.Request) string {
	remoteIP := r.RemoteAddr
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		remoteIP = ip
	}
	trustedProxy := false
	for _, rawCIDR := range strings.Split(os.Getenv("TRUSTED_PROXY_CIDRS"), ",") {
		_, network, err := net.ParseCIDR(strings.TrimSpace(rawCIDR))
		if err == nil && network.Contains(net.ParseIP(remoteIP)) {
			trustedProxy = true
			break
		}
	}
	if trustedProxy {
		if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
			// The first address is the original client only when the proxy chain is trusted.
			if idx := strings.Index(ip, ","); idx != -1 {
				return strings.TrimSpace(ip[:idx])
			}
			return strings.TrimSpace(ip)
		}
		if ip := r.Header.Get("X-Real-IP"); ip != "" {
			return strings.TrimSpace(ip)
		}
	}
	// Fall back to RemoteAddr, handling both IPv4 and IPv6
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr might not have a port (unlikely but handle it)
		return r.RemoteAddr
	}
	return ip
}

// isNoisyPath reports whether a request is routine infrastructure traffic
// (health probes, SPA static assets) that should only appear in access logs
// at debug level, so INFO stays focused on real API usage.
func isNoisyPath(path string) bool {
	if path == "/healthz" || path == "/readyz" || path == "/favicon.ico" {
		return true
	}
	return !strings.HasPrefix(path, "/api/") && !strings.HasPrefix(path, "/swagger/")
}

func AccessLogHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Header.Get("X-Request-ID") == "" {
			r.Header.Set("X-Request-ID", requestID())
		}
		w.Header().Set("X-Request-ID", r.Header.Get("X-Request-ID"))
		r, audit := withAuditContext(r)
		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}
		defer func() {
			if recovered := recover(); recovered != nil {
				utils.LogError("http_panic_recovered", map[string]interface{}{
					"request_id": r.Header.Get("X-Request-ID"),
					"error":      fmt.Sprint(recovered),
				})
				if !rw.headerWritten {
					writeError(rw, r, http.StatusInternalServerError, ErrInternalError, "internal server error")
				}
			}
		}()

		next.ServeHTTP(rw, r)

		username := audit.username
		if username == "" {
			username = "anonymous"
		}
		// Health probes and static assets are logged at debug only; API calls
		// always produce one access line with user, IP and user-agent.
		if utils.IsDebugLevel() || !isNoisyPath(r.URL.Path) {
			utils.LogAccess(r.Header.Get("X-Request-ID"), getClientIP(r), username, r.UserAgent(), r.Method, r.URL.Path, requestCluster(r), rw.statusCode, rw.size, time.Since(start))
		}
	})
}

func CompressHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead ||
			!strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") ||
			r.Header.Get("Range") != "" ||
			w.Header().Get("Content-Encoding") != "" {
			next.ServeHTTP(w, r)
			return
		}

		gz, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		wrapped := &gzipResponseWriter{ResponseWriter: w, gzipWriter: gz}
		next.ServeHTTP(wrapped, r)
		if wrapped.enabled {
			_ = gz.Close()
		}
	})
}
