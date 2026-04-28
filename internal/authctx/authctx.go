// Package authctx provides a small, centralized way to access authx principal data from context.
package authctx

import (
	"context"
	"strings"

	"github.com/arcgolabs/authx"
	"github.com/arcgolabs/httpx"
)

// Current returns the current principal from ctx when present.
func Current(ctx context.Context) (authx.Principal, bool) {
	p, ok := authx.PrincipalFromContextAs[authx.Principal](ctx)
	if !ok || strings.TrimSpace(p.ID) == "" {
		return authx.Principal{}, false
	}
	return p, true
}

// MustCurrent returns the current principal or a stable 401 error.
func MustCurrent(ctx context.Context) (authx.Principal, error) {
	p, ok := Current(ctx)
	if ok {
		return p, nil
	}
	return authx.Principal{}, httpx.NewError(401, "unauthorized")
}

// UserID returns the current principal ID when present.
func UserID(ctx context.Context) (string, bool) {
	p, ok := Current(ctx)
	if !ok {
		return "", false
	}
	return strings.TrimSpace(p.ID), true
}

