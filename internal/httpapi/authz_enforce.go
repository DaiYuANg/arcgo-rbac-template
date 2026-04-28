package httpapi

import (
	"context"
	"fmt"

	"github.com/arcgolabs/arcgo-rbac-template/internal/authctx"
	"github.com/arcgolabs/authx"
	"github.com/arcgolabs/httpx"
)

func enforce(ctx context.Context, engine *authx.Engine, action, resource string) error {
	if engine == nil {
		return httpx.NewError(500, "auth_engine_missing")
	}
	p, err := authctx.MustCurrent(ctx)
	if err != nil {
		return httpx.NewError(401, "unauthorized", fmt.Errorf("principal missing: %w", err))
	}
	decision, err := engine.Can(ctx, authx.AuthorizationModel{
		Principal: p,
		Action:    action,
		Resource:  resource,
	})
	if err != nil {
		return httpx.NewError(500, "unknown", err)
	}
	if !decision.Allowed {
		return httpx.NewError(403, "forbidden")
	}
	return nil
}
