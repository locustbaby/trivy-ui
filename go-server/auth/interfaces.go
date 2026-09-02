package auth

import (
	"context"
	"net/http"
)

type IdentityProvider interface {
	Authenticate(context.Context, string, string) (Principal, error)
	Resolve(context.Context, string) (Principal, error)
}

type PolicyProvider interface {
	ScopesFor(context.Context, Principal) (ScopeSnapshot, error)
}

type SessionManager interface {
	Create(http.ResponseWriter, Principal) error
	Read(*http.Request) (Session, error)
	Clear(http.ResponseWriter)
}
