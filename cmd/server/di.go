package main

import (
	"context"
	"fmt"
	"log/slog"
	"sort"

	"github.com/arcgolabs/arcgo-rbac-template/internal/authz"
	"github.com/arcgolabs/arcgo-rbac-template/internal/config"
	"github.com/arcgolabs/arcgo-rbac-template/internal/db"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/application"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/infra/dbxrepo"
	"github.com/arcgolabs/authx"
	authjwt "github.com/arcgolabs/authx/jwt"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dix"
	"github.com/arcgolabs/httpx"
	"github.com/arcgolabs/httpx/adapter"
	adapterfiber "github.com/arcgolabs/httpx/adapter/fiber"
	"github.com/gofiber/fiber/v2"
)

func rbacModule(rootCtx context.Context) dix.Module {
	return dix.NewModule(
		"rbac-template",
		dix.Providers(
			dix.ProviderErr2(func(cfg config.Config, logger *slog.Logger) (*DBHandle, error) {
				core, dialect, err := db.Open(rootCtx, cfg.DB, logger)
				if err != nil {
					return nil, fmt.Errorf("db open: %w", err)
				}
				return &DBHandle{Core: core, Dialect: dialect}, nil
			}),
			dix.Provider1(func(h *DBHandle) *dbx.DB {
				if h == nil || h.Core == nil {
					return nil
				}
				return h.Core
			}),
			dix.ProviderErr2(func(cfg config.Config, h *DBHandle) (domain.UserRepository, error) {
				_ = cfg
				if h == nil || h.Core == nil {
					return nil, context.Canceled
				}
				return dbxrepo.NewUserRepo(h.Core, h.Dialect), nil
			}),
			dix.ProviderErr2(func(cfg config.Config, h *DBHandle) (domain.RoleRepository, error) {
				_ = cfg
				if h == nil || h.Core == nil {
					return nil, context.Canceled
				}
				return dbxrepo.NewRoleRepo(h.Core, h.Dialect), nil
			}),
			dix.ProviderErr1(func(h *DBHandle) (domain.PermissionRepository, error) {
				if h == nil || h.Core == nil {
					return nil, context.Canceled
				}
				return dbxrepo.NewPermissionRepo(h.Core), nil
			}),
			dix.ProviderErr2(func(cfg config.Config, h *DBHandle) (domain.PermissionGroupRepository, error) {
				_ = cfg
				if h == nil || h.Core == nil {
					return nil, context.Canceled
				}
				return dbxrepo.NewPermissionGroupRepo(h.Core, h.Dialect), nil
			}),
			dix.Provider2(application.NewAuthorizer),
			dix.ProviderErr3(newAuthEngine),
			dix.Provider0(func() *fiber.App { return fiber.New() }),
			dix.Provider2(func(app *fiber.App, logger *slog.Logger) *adapterfiber.Adapter {
				_ = logger
				return adapterfiber.New(app, adapter.HumaOptions{
					Title:       "arcgo-rbac-template",
					Version:     "0.1.0",
					Description: "RBAC template (authx + httpx + dix + dbx + configx)",
					DocsPath:    "/docs",
					OpenAPIPath: "/openapi.json",
				})
			}),
			dix.Provider2(func(a *adapterfiber.Adapter, logger *slog.Logger) httpx.ServerRuntime {
				return httpx.New(
					httpx.WithAdapter(a),
					httpx.WithLogger(logger),
					httpx.WithAccessLog(true),
					httpx.WithValidation(),
				)
			}),
		),
		dix.Hooks(
			dix.OnStart3(func(ctx context.Context, cfg config.Config, server httpx.ServerRuntime, _ *fiber.App) error {
				logRouteSummary(server, slog.Default())
				go runHTTPServer(ctx, cfg, server)
				return nil
			}),
			dix.OnStop2(func(_ context.Context, server httpx.ServerRuntime, dbh *DBHandle) error {
				return shutdownServerAndDB(server, dbh)
			}),
		),
	)
}

func newAuthEngine(cfg config.Config, iamAuthz *application.Authorizer, passwordProvider authx.AuthenticationProvider) (*authx.Engine, error) {
	engine := authx.NewEngine()
	if err := engine.RegisterProvider(
		authjwt.NewAuthenticationProvider(
			authjwt.WithHMACSecret([]byte(cfg.Auth.JWTSecret)),
		),
	); err != nil {
		return nil, fmt.Errorf("register jwt provider: %w", err)
	}
	if passwordProvider != nil {
		if err := engine.RegisterProvider(passwordProvider); err != nil {
			return nil, fmt.Errorf("register password provider: %w", err)
		}
	}
	engine.SetAuthorizer(authz.NewIAMAuthorizer(iamAuthz))
	return engine, nil
}

func runHTTPServer(ctx context.Context, cfg config.Config, server httpx.ServerRuntime) {
	slog.Default().Info("listening", "addr", cfg.HTTP.Addr, "stack", "httpx/fiber")
	if err := server.ListenAndServeContext(ctx, cfg.HTTP.Addr); err != nil {
		slog.Default().Error("server listen failed", "error", err)
	}
}

func shutdownServerAndDB(server httpx.ServerRuntime, dbh *DBHandle) error {
	if err := server.Shutdown(); err != nil {
		slog.Default().Error("server shutdown failed", "error", err)
	}
	if dbh != nil && dbh.Core != nil {
		if err := dbh.Core.Close(); err != nil {
			slog.Default().Error("db close failed", "error", err)
		}
	}
	return nil
}

func logRouteSummary(server httpx.ServerRuntime, logger *slog.Logger) {
	if server == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}

	total := server.RouteCount()
	authRoutes := server.GetRoutesByPath("/api/auth")
	methodGroups := server.GetRoutesGroupedByMethod()

	methodCounts := map[string]int{}
	if methodGroups != nil {
		methodGroups.Range(func(method string, routes []httpx.RouteInfo) bool {
			methodCounts[method] = len(routes)
			return true
		})
	}

	methods := make([]string, 0, len(methodCounts))
	for method := range methodCounts {
		methods = append(methods, method)
	}
	sort.Strings(methods)
	orderedCounts := make([]string, 0, len(methods))
	for _, method := range methods {
		orderedCounts = append(orderedCounts, fmt.Sprintf("%s:%d", method, methodCounts[method]))
	}

	logger.Info("http routes ready",
		"total", total,
		"auth_routes", authRoutes.Len(),
		"methods", orderedCounts,
	)
}
