package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionRoundTripAndTamper(t *testing.T) {
	manager, err := NewCookieSessionManager([]byte("01234567890123456789012345678901"), time.Hour, false, "lax")
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	if err := manager.Create(response, Principal{Subject: "alice"}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/", nil)
	request.AddCookie(response.Result().Cookies()[0])
	if session, err := manager.Read(request); err != nil || session.Subject != "alice" {
		t.Fatalf("Read() = %#v, %v", session, err)
	}
	tampered := httptest.NewRequest("GET", "/", nil)
	cookie := *response.Result().Cookies()[0]
	cookie.Value += "x"
	tampered.AddCookie(&cookie)
	if _, err := manager.Read(tampered); err == nil {
		t.Fatal("tampered session should be rejected")
	}
}

func TestSessionSameSitePolicy(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	manager, err := NewCookieSessionManager(secret, time.Hour, true, "none")
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	if err := manager.Create(response, Principal{Subject: "alice"}); err != nil {
		t.Fatal(err)
	}
	cookie := response.Result().Cookies()[0]
	if cookie.SameSite != http.SameSiteNoneMode || !cookie.Secure {
		t.Fatalf("cookie policy = SameSite %v, Secure %v; want None, true", cookie.SameSite, cookie.Secure)
	}
	if _, err := NewCookieSessionManager(secret, time.Hour, false, "none"); err == nil {
		t.Fatal("SameSite=None with an insecure cookie must be rejected")
	}
	if _, err := NewCookieSessionManager(secret, time.Hour, true, "unknown"); err == nil {
		t.Fatal("unknown SameSite policy must be rejected")
	}
}
