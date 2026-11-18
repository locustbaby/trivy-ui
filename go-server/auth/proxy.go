package auth

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ProxyConfig configures AUTH_MODE=proxy: an authenticating reverse proxy
// (Authelia, oauth2-proxy, ...) signs the user in and passes the identity in
// request headers. The headers are only trusted from TrustedCIDRs.
type ProxyConfig struct {
	UserHeader   string
	GroupsHeader string
	TrustedCIDRs string
}

type ProxyAuthenticator struct {
	userHeader   string
	groupsHeader string
	trusted      []*net.IPNet
}

func NewProxyAuthenticator(cfg ProxyConfig) (*ProxyAuthenticator, error) {
	userHeader := strings.TrimSpace(cfg.UserHeader)
	if userHeader == "" {
		return nil, fmt.Errorf("AUTH_PROXY_USER_HEADER cannot be empty")
	}
	var trusted []*net.IPNet
	for _, raw := range strings.Split(cfg.TrustedCIDRs, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid AUTH_PROXY_TRUSTED_CIDRS entry %q: %w", raw, err)
		}
		trusted = append(trusted, network)
	}
	// Without a trusted source anyone who can reach the pod could send the
	// identity headers themselves.
	if len(trusted) == 0 {
		return nil, fmt.Errorf("AUTH_MODE=proxy requires AUTH_PROXY_TRUSTED_CIDRS")
	}
	return &ProxyAuthenticator{userHeader: userHeader, groupsHeader: strings.TrimSpace(cfg.GroupsHeader), trusted: trusted}, nil
}

// Authenticate returns the principal named by the proxy headers. Proxy users
// get unrestricted read scope: access control is the proxy's job.
func (p *ProxyAuthenticator) Authenticate(r *http.Request) (Principal, ScopeSnapshot, error) {
	if !p.fromTrustedProxy(r) {
		return Principal{}, ScopeSnapshot{}, fmt.Errorf("request did not come from a trusted proxy")
	}
	username := strings.ToLower(strings.TrimSpace(r.Header.Get(p.userHeader)))
	if username == "" {
		return Principal{}, ScopeSnapshot{}, fmt.Errorf("missing %s header", p.userHeader)
	}
	var groups []string
	if p.groupsHeader != "" {
		for _, group := range strings.Split(r.Header.Get(p.groupsHeader), ",") {
			if group = strings.TrimSpace(group); group != "" {
				groups = append(groups, group)
			}
		}
	}
	return Principal{Subject: username, Username: username, Groups: groups}, UnrestrictedScope(), nil
}

func (p *ProxyAuthenticator) fromTrustedProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, network := range p.trusted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
