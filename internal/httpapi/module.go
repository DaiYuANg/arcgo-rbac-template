package httpapi

import (
	"context"

	"github.com/arcgolabs/arcgo-rbac-template/internal/config"
	"github.com/arcgolabs/authx"
	"github.com/DaiYuANg/arcgo/kvx"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dix"
	"github.com/arcgolabs/httpx"
	"github.com/gofiber/fiber/v2"
)

// Endpoint is the dix collection role for httpx endpoint modules.
// httpx accepts endpoints as `any`, so this is intentionally an empty interface.
type Endpoint interface{}

func Module() dix.Module {
	return dix.NewModule("httpapi",
		dix.Providers(
			dix.Provider0(func() *HealthEndpoint { return &HealthEndpoint{} },
				dix.Into[Endpoint](dix.Key("health"), dix.Order(-100)),
			),
			dix.Provider3(func(cfg config.Config, engine *authx.Engine, cache kvx.KV) *AuthEndpoint {
				return &AuthEndpoint{cfg: cfg, engine: engine, cache: cache, cachePrefix: cfg.KV.Prefix}
			}, dix.Into[Endpoint](dix.Key("auth"), dix.Order(-50))),
			dix.Provider4(func(cfg config.Config, engine *authx.Engine, core *dbx.DB, cache kvx.KV) *MeEndpoint {
				return &MeEndpoint{engine: engine, core: core, cache: cache, cachePrefix: cfg.KV.Prefix, cacheTTL: cfg.KV.DefaultTTL}
			},
				dix.Into[Endpoint](dix.Key("me"), dix.Order(0)),
				dix.Into[FiberBinder](dix.Key("me"), dix.Order(0)),
			),
			dix.Provider4(func(cfg config.Config, engine *authx.Engine, core *dbx.DB, cache kvx.KV) *UsersResource {
				return &UsersResource{engine: engine, core: core, cache: cache, cachePrefix: cfg.KV.Prefix, cacheTTL: cfg.KV.DefaultTTL}
			},
				dix.Into[Endpoint](dix.Key("users"), dix.Order(10)),
				dix.Into[FiberBinder](dix.Key("users"), dix.Order(10)),
			),
			dix.Provider1(func(core *dbx.DB) *DashboardEndpoint {
				return &DashboardEndpoint{core: core}
			}, dix.Into[Endpoint](dix.Key("dashboard"), dix.Order(15))),
			dix.Provider2(func(engine *authx.Engine, core *dbx.DB) *RolesResource {
				return &RolesResource{engine: engine, core: core}
			},
				dix.Into[Endpoint](dix.Key("roles"), dix.Order(20)),
				dix.Into[FiberBinder](dix.Key("roles"), dix.Order(20)),
			),
			dix.Provider2(func(engine *authx.Engine, core *dbx.DB) *PermissionsResource {
				return &PermissionsResource{engine: engine, core: core}
			},
				dix.Into[Endpoint](dix.Key("permissions"), dix.Order(30)),
				dix.Into[FiberBinder](dix.Key("permissions"), dix.Order(30)),
			),
			dix.Provider2(func(engine *authx.Engine, core *dbx.DB) *PermissionGroupsResource {
				return &PermissionGroupsResource{engine: engine, core: core}
			},
				dix.Into[Endpoint](dix.Key("permission_groups"), dix.Order(40)),
				dix.Into[FiberBinder](dix.Key("permission_groups"), dix.Order(40)),
			),
		),
		dix.Hooks(
			dix.OnStart2(func(_ context.Context, app *fiber.App, binders []FiberBinder) error {
				for _, binder := range binders {
					if binder == nil {
						continue
					}
					b := binder.FiberBinding()
					if b.Prefix == "" || b.Handler == nil {
						continue
					}
					app.Use(b.Prefix, b.Handler)
				}
				return nil
			}),
			dix.OnStart2(func(_ context.Context, server httpx.ServerRuntime, endpoints []Endpoint) error {
				for _, ep := range endpoints {
					server.Register(ep)
				}
				return nil
			}),
		),
	)
}

