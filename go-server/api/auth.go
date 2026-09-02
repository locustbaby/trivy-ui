package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"trivy-ui/auth"
	"trivy-ui/utils"
)

type authContextKey struct{}

type RequestAuth struct {
	Principal auth.Principal
	Access    auth.AccessSnapshot
}

func withRequestAuth(ctx context.Context, value RequestAuth) context.Context {
	return context.WithValue(ctx, authContextKey{}, value)
}

func requestAuth(r *http.Request) RequestAuth {
	if value, ok := r.Context().Value(authContextKey{}).(RequestAuth); ok {
		return value
	}
	return RequestAuth{
		Principal: auth.Principal{Subject: "anonymous", Username: "anonymous"},
		Access:    auth.NewAccessSnapshot(auth.UnrestrictedScope(), auth.UnrestrictedScope()),
	}
}

func (h *Handler) authenticateRequest(r *http.Request) (RequestAuth, int) {
	if h.auth == nil || !h.auth.IsEnabled() {
		return RequestAuth{Principal: auth.Principal{Subject: "anonymous", Username: "anonymous"}, Access: h.accessSnapshot(auth.UnrestrictedScope())}, http.StatusOK
	}
	session, err := h.auth.Session().Read(r)
	if err != nil {
		return RequestAuth{}, http.StatusUnauthorized
	}
	principal, scope, err := h.auth.Resolve(r.Context(), session.Subject)
	if err != nil {
		return RequestAuth{}, http.StatusUnauthorized
	}
	return RequestAuth{Principal: principal, Access: h.accessSnapshot(scope)}, http.StatusOK
}

func (h *Handler) accessSnapshot(userScope auth.ScopeSnapshot) auth.AccessSnapshot {
	if h.dataAccess == nil {
		return auth.NewAccessSnapshot(userScope, auth.UnrestrictedScope())
	}
	return auth.NewAccessSnapshot(userScope, h.dataAccess.Scope())
}

func (h *Handler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestAuth, status := h.authenticateRequest(r)
		if status != http.StatusOK {
			writeError(w, r, status, ErrAuthRequired, "authentication required")
			return
		}
		auditFromRequest(r).username = requestAuth.Principal.Username
		next.ServeHTTP(w, r.WithContext(withRequestAuth(r.Context(), requestAuth)))
	})
}

// AccessContextMiddleware supplies the data-source scope when authentication
// is disabled. Keeping this separate from AuthMiddleware preserves namespace
// restrictions without making disabled authentication look like a login gate.
func (h *Handler) AccessContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestAuth := RequestAuth{
			Principal: auth.Principal{Subject: "anonymous", Username: "anonymous"},
			Access:    h.accessSnapshot(auth.UnrestrictedScope()),
		}
		next.ServeHTTP(w, r.WithContext(withRequestAuth(r.Context(), requestAuth)))
	})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	markDeprecated(w, r, "/api/v1/auth/login")
	if h.auth == nil || !h.auth.IsEnabled() {
		writeJSON(w, http.StatusOK, Response{Code: CodeSuccess, Message: "Authentication disabled", Data: map[string]interface{}{"mode": "none"}})
		return
	}
	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		utils.LogWarning("auth_login_invalid_request", map[string]interface{}{
			"src_ip": getClientIP(r),
			"user":   "unknown",
		})
		writeError(w, r, http.StatusBadRequest, ErrValidationFailed, "invalid request")
		return
	}
	username := strings.ToLower(strings.TrimSpace(request.Username))
	principal, err := h.auth.Authenticate(r.Context(), request.Username, request.Password)
	if err != nil {
		utils.LogWarning("auth_login_failed", map[string]interface{}{
			"src_ip": getClientIP(r),
			"user":   username,
		})
		writeError(w, r, http.StatusUnauthorized, ErrAuthRequired, "invalid username or password")
		return
	}
	if err := h.auth.Session().Create(w, principal); err != nil {
		utils.LogError("auth_session_create_failed", map[string]interface{}{
			"src_ip": getClientIP(r),
			"user":   principal.Username,
			"error":  err.Error(),
		})
		writeError(w, r, http.StatusInternalServerError, ErrInternalError, "failed to create session")
		return
	}
	_, scope, err := h.auth.Resolve(r.Context(), principal.Subject)
	if err != nil {
		utils.LogError("auth_permission_resolve_failed", map[string]interface{}{
			"src_ip": getClientIP(r),
			"user":   principal.Username,
			"error":  err.Error(),
		})
		writeError(w, r, http.StatusServiceUnavailable, ErrProviderUnavailable, "failed to resolve permissions")
		return
	}
	utils.LogInfo("auth_login_succeeded", map[string]interface{}{
		"src_ip": getClientIP(r),
		"user":   principal.Username,
		"groups": principal.Groups,
	})
	writeJSON(w, http.StatusOK, Response{Code: CodeSuccess, Message: "Login successful", Data: map[string]interface{}{
		"username": principal.Username,
		"groups":   principal.Groups,
		"scope":    scope.Fingerprint,
		"provider": "local",
		"methods":  []string{"password"},
	}})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	markDeprecated(w, r, "/api/v1/auth/logout")
	username := "anonymous"
	if h.auth != nil && h.auth.Session() != nil {
		if session, err := h.auth.Session().Read(r); err == nil {
			if principal, _, err := h.auth.Resolve(r.Context(), session.Subject); err == nil {
				username = principal.Username
			}
		}
		h.auth.Session().Clear(w)
	}
	utils.LogInfo("auth_logout", map[string]interface{}{
		"src_ip": getClientIP(r),
		"user":   username,
	})
	writeJSON(w, http.StatusOK, Response{Code: CodeSuccess, Message: "Logout successful"})
}

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	markDeprecated(w, r, "/api/v1/auth/me")
	if h.auth == nil || !h.auth.IsEnabled() {
		writeJSON(w, http.StatusOK, Response{Code: CodeSuccess, Message: "Authentication disabled", Data: map[string]interface{}{
			"enabled":       false,
			"mode":          "none",
			"authenticated": false,
			"provider":      "none",
			"methods":       []string{},
		}})
		return
	}
	requestAuth, status := h.authenticateRequest(r)
	if status != http.StatusOK {
		writeJSON(w, http.StatusUnauthorized, Response{Code: CodeError, Message: "Authentication required", Data: map[string]interface{}{
			"enabled":       true,
			"mode":          "local",
			"authenticated": false,
			"provider":      "local",
			"methods":       []string{"password"},
		}, Error: &APIError{Type: "AUTH_REQUIRED", RequestID: w.Header().Get("X-Request-ID")}})
		return
	}
	auditFromRequest(r).username = requestAuth.Principal.Username
	writeJSON(w, http.StatusOK, Response{Code: CodeSuccess, Message: "Authenticated", Data: map[string]interface{}{
		"enabled":       true,
		"mode":          "local",
		"authenticated": true,
		"provider":      "local",
		"methods":       []string{"password"},
		"username":      requestAuth.Principal.Username,
		"groups":        requestAuth.Principal.Groups,
	}})
}
