package httpapi

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/DaiYuANg/arcgo/kvx"
	"github.com/arcgolabs/arcgo-rbac-template/internal/authctx"
	iamservice "github.com/arcgolabs/arcgo-rbac-template/internal/iam/application/service"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/authx"
	"github.com/arcgolabs/httpx"
	"github.com/danielgtaylor/huma/v2"
)

type MeEndpoint struct {
	engine      *authx.Engine
	svc         iamservice.MeService
	cache       kvx.KV
	cachePrefix string
	cacheTTL    time.Duration
}

func (e *MeEndpoint) FiberBinding() FiberBinding {
	return FiberBinding{
		Prefix:  "/api/me",
		Handler: requireAuthFiber(e.engine),
	}
}

func (e *MeEndpoint) EndpointSpec() httpx.EndpointSpec {
	return httpx.EndpointSpec{
		Prefix:        "/api/me",
		Tags:          httpx.Tags("me"),
		SummaryPrefix: "Me",
		Description:   "Current principal endpoints",
	}
}

func (e *MeEndpoint) Register(registrar httpx.Registrar) {
	g := registrar.Scope()
	httpx.MustGroupGet(g, "", e.Get, func(op *huma.Operation) {
		op.Summary = "Get current principal"
	})
}

func (e *MeEndpoint) Get(ctx context.Context, _ *struct{}) (*JSONBody[MeResponse], error) {
	p, err := authctx.MustCurrent(ctx)
	if err != nil {
		return nil, httpx.NewError(401, "unauthorized")
	}
	uid := strings.TrimSpace(p.ID)
	if uid == "" {
		return nil, httpx.NewError(401, "unauthorized")
	}

	if cached, ok := e.cacheGet(ctx, uid); ok {
		return wrapJSON(cached), nil
	}

	jwtRoles := jwtRoleIDs(p)
	me, err := e.svc.GetMe(ctx, domain.UserID(uid), jwtRoles)
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	roleRefs := make([]RoleRef, 0, len(me.Roles))
	for _, rr := range me.Roles {
		roleRefs = append(roleRefs, RoleRef{ID: string(rr.ID), Name: rr.Name})
	}

	resp := &MeResponse{
		ID:          uid,
		Name:        me.Name,
		Email:       me.Email,
		Roles:       roleRefs,
		Permissions: me.Permissions,
	}

	e.cacheSet(ctx, uid, resp)
	return wrapJSON(resp), nil
}

func jwtRoleIDs(p authx.Principal) []domain.RoleID {
	if p.Roles == nil {
		return nil
	}
	raw := p.Roles.Values()
	out := make([]domain.RoleID, 0, len(raw))
	for _, rid := range raw {
		rid = strings.TrimSpace(rid)
		if rid != "" {
			out = append(out, domain.RoleID(rid))
		}
	}
	return out
}

func (e *MeEndpoint) cacheKey(uid string) string {
	return strings.TrimSpace(e.cachePrefix) + "me:" + uid
}

func (e *MeEndpoint) cacheGet(ctx context.Context, uid string) (*MeResponse, bool) {
	if e.cache == nil {
		return nil, false
	}
	key := e.cacheKey(uid)
	raw, err := e.cache.Get(ctx, key)
	if err != nil || len(raw) == 0 {
		return nil, false
	}
	var cached MeResponse
	if jsonErr := jsonUnmarshal(raw, &cached); jsonErr != nil || cached.ID == "" {
		return nil, false
	}
	return &cached, true
}

func (e *MeEndpoint) cacheSet(ctx context.Context, uid string, resp *MeResponse) {
	if e.cache == nil || resp == nil {
		return
	}
	bytes, err := jsonMarshal(resp)
	if err != nil {
		return
	}
	ttl := e.cacheTTL
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	if err := e.cache.Set(ctx, e.cacheKey(uid), bytes, ttl); err != nil {
		slog.Default().Error("me cache set failed", "error", err)
	}
}
