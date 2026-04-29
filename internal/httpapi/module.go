package httpapi

import (
	"context"
	"log/slog"

	"github.com/DaiYuANg/arcgo/kvx"
	"github.com/arcgolabs/arcgo-rbac-template/internal/config"
	iamservice "github.com/arcgolabs/arcgo-rbac-template/internal/iam/application/service"
	"github.com/arcgolabs/authx"
	"github.com/arcgolabs/collectionx"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dix"
	"github.com/arcgolabs/httpx"
	"github.com/gofiber/fiber/v2"
)

func Module() dix.Module {
	return dix.NewModule("httpapi",
		dix.Providers(
			dix.Provider0(func() *HealthEndpoint { return &HealthEndpoint{} },
				dix.Into[httpx.Endpoint](dix.Key("health"), dix.Order(-100)),
			),
			dix.Provider5(func(cfg config.Config, engine *authx.Engine, cache kvx.KV, logger *slog.Logger, core *dbx.DB) *AuthEndpoint {
				return &AuthEndpoint{
					cfg:         cfg,
					engine:      engine,
					cache:       cache,
					cachePrefix: cfg.KV.Prefix,
					core:        core,
					logger:      logger,
					auditSink:   newAuthAuditSink(core, logger),
				}
			}, dix.Into[httpx.Endpoint](dix.Key("auth"), dix.Order(-50))),
			dix.Provider4(func(cfg config.Config, engine *authx.Engine, svc iamservice.MeService, cache kvx.KV) *MeEndpoint {
				return &MeEndpoint{engine: engine, svc: svc, cache: cache, cachePrefix: cfg.KV.Prefix, cacheTTL: cfg.KV.DefaultTTL}
			},
				dix.Into[httpx.Endpoint](dix.Key("me"), dix.Order(0)),
				dix.Into[FiberBinder](dix.Key("me"), dix.Order(0)),
			),
			dix.Provider3(func(cfg config.Config, engine *authx.Engine, svc iamservice.UsersService) *UsersResource {
				return &UsersResource{engine: engine, svc: svc, cacheTTL: cfg.KV.DefaultTTL}
			},
				dix.Into[httpx.Endpoint](dix.Key("users"), dix.Order(10)),
				dix.Into[FiberBinder](dix.Key("users"), dix.Order(10)),
			),
			dix.Provider1(func(core *dbx.DB) *DashboardEndpoint {
				return &DashboardEndpoint{core: core}
			}, dix.Into[httpx.Endpoint](dix.Key("dashboard"), dix.Order(15))),
			dix.Provider2(func(engine *authx.Engine, svc iamservice.RolesService) *RolesResource {
				return &RolesResource{engine: engine, svc: svc}
			},
				dix.Into[httpx.Endpoint](dix.Key("roles"), dix.Order(20)),
				dix.Into[FiberBinder](dix.Key("roles"), dix.Order(20)),
			),
			dix.Provider2(func(engine *authx.Engine, svc iamservice.PermissionsService) *PermissionsResource {
				return &PermissionsResource{engine: engine, svc: svc}
			},
				dix.Into[httpx.Endpoint](dix.Key("permissions"), dix.Order(30)),
				dix.Into[FiberBinder](dix.Key("permissions"), dix.Order(30)),
			),
			dix.Provider2(func(engine *authx.Engine, svc iamservice.PermissionGroupsService) *PermissionGroupsResource {
				return &PermissionGroupsResource{engine: engine, svc: svc}
			},
				dix.Into[httpx.Endpoint](dix.Key("permission_groups"), dix.Order(40)),
				dix.Into[FiberBinder](dix.Key("permission_groups"), dix.Order(40)),
			),
		),
		dix.Hooks(
			dix.OnStart2(func(_ context.Context, app *fiber.App, binders collectionx.List[FiberBinder]) error {
				wireFiberBinders(app, binders)
				return nil
			}),
			dix.OnStart2(func(_ context.Context, server httpx.ServerRuntime, endpoints collectionx.List[httpx.Endpoint]) error {
				wireHTTPEndpoints(server, endpoints)
				return nil
			}),
		),
	)
}
