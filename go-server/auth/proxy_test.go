package auth

import (
	"net/http/httptest"
	"testing"
)

func TestProxyAuthenticatorRequiresTrustedCIDRs(t *testing.T) {
	if _, err := NewProxyAuthenticator(ProxyConfig{UserHeader: "Remote-User"}); err == nil {
		t.Fatal("proxy mode without trusted CIDRs must be rejected")
	}
	if _, err := NewProxyAuthenticator(ProxyConfig{UserHeader: "Remote-User", TrustedCIDRs: "not-a-cidr"}); err == nil {
		t.Fatal("invalid CIDR must be rejected")
	}
}

func TestProxyAuthenticatorTrustsHeadersOnlyFromProxy(t *testing.T) {
	proxy, err := NewProxyAuthenticator(ProxyConfig{UserHeader: "Remote-User", GroupsHeader: "Remote-Groups", TrustedCIDRs: "10.42.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest("GET", "/api/v1/overview", nil)
	request.Header.Set("Remote-User", " Alice ")
	request.Header.Set("Remote-Groups", "admins, dev,,")
	request.RemoteAddr = "10.42.0.7:51234"
	principal, scope, err := proxy.Authenticate(request)
	if err != nil {
		t.Fatalf("trusted proxy request rejected: %v", err)
	}
	if principal.Username != "alice" || len(principal.Groups) != 2 || principal.Groups[0] != "admins" || principal.Groups[1] != "dev" {
		t.Fatalf("unexpected principal %+v", principal)
	}
	if !scope.IsUnrestricted() {
		t.Fatal("proxy users get unrestricted read scope")
	}

	request.RemoteAddr = "192.168.0.10:51234"
	if _, _, err := proxy.Authenticate(request); err == nil {
		t.Fatal("headers from an untrusted address must be ignored")
	}

	request.RemoteAddr = "10.42.0.7:51234"
	request.Header.Del("Remote-User")
	if _, _, err := proxy.Authenticate(request); err == nil {
		t.Fatal("missing user header must fail")
	}
}

func TestNewServiceProxyMode(t *testing.T) {
	service, err := NewService(Config{Mode: "proxy", Proxy: ProxyConfig{UserHeader: "Remote-User", TrustedCIDRs: "127.0.0.1/32"}})
	if err != nil {
		t.Fatal(err)
	}
	if !service.IsEnabled() || !service.IsProxy() || service.Proxy() == nil || service.Session() != nil {
		t.Fatalf("unexpected proxy service state: %+v", service)
	}
}
