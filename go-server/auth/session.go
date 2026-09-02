package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const CookieName = "trivy-ui-session"

type Session struct {
	Subject string
	Expiry  time.Time
}

type CookieSessionManager struct {
	secret   []byte
	duration time.Duration
	secure   bool
}

type sessionPayload struct {
	Subject string `json:"sub"`
	Expiry  int64  `json:"exp"`
}

func NewCookieSessionManager(secret []byte, duration time.Duration, secure bool) (*CookieSessionManager, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("session secret must be at least 32 bytes")
	}
	if duration <= 0 {
		return nil, fmt.Errorf("session duration must be positive")
	}
	return &CookieSessionManager{secret: append([]byte(nil), secret...), duration: duration, secure: secure}, nil
}

func (m *CookieSessionManager) Create(w http.ResponseWriter, principal Principal) error {
	expiry := time.Now().Add(m.duration).UTC()
	payload := sessionPayload{Subject: principal.Subject, Expiry: expiry.Unix()}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	value := base64.RawURLEncoding.EncodeToString(raw) + "." + m.sign(raw)
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		Expires:  expiry,
		MaxAge:   int(m.duration.Seconds()),
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (m *CookieSessionManager) Read(r *http.Request) (Session, error) {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		return Session{}, err
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return Session{}, fmt.Errorf("invalid session")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	providedMAC, macErr := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || macErr != nil || !hmac.Equal(providedMAC, m.mac(raw)) {
		return Session{}, fmt.Errorf("invalid session signature")
	}
	var payload sessionPayload
	if err := json.Unmarshal(raw, &payload); err != nil || payload.Subject == "" {
		return Session{}, fmt.Errorf("invalid session payload")
	}
	expiry := time.Unix(payload.Expiry, 0)
	if !expiry.After(time.Now()) {
		return Session{}, fmt.Errorf("session expired")
	}
	return Session{Subject: payload.Subject, Expiry: expiry}, nil
}

func (m *CookieSessionManager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0), HttpOnly: true, Secure: m.secure, SameSite: http.SameSiteLaxMode})
}

func (m *CookieSessionManager) sign(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(m.mac(raw))
}

func (m *CookieSessionManager) mac(raw []byte) []byte {
	h := hmac.New(sha256.New, m.secret)
	_, _ = h.Write(raw)
	return h.Sum(nil)
}

func ParseDuration(value string, fallback time.Duration) (time.Duration, error) {
	if value == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", value, err)
	}
	return duration, nil
}

func ExpiryString(expiry time.Time) string {
	return strconv.FormatInt(expiry.Unix(), 10)
}
