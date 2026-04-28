package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/arcgolabs/arcgo-rbac-template/internal/authn"
	"github.com/arcgolabs/arcgo-rbac-template/internal/authz"
	"github.com/arcgolabs/arcgo-rbac-template/internal/config"
	"github.com/arcgolabs/arcgo-rbac-template/internal/db"
	"github.com/arcgolabs/arcgo-rbac-template/internal/httpapi"
	"github.com/arcgolabs/arcgo-rbac-template/internal/kv"
	"github.com/arcgolabs/arcgo-rbac-template/internal/logger"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/application"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/infra/dbxrepo"
	"github.com/arcgolabs/authx"
	authjwt "github.com/arcgolabs/authx/jwt"
	"github.com/arcgolabs/dix"
	"github.com/arcgolabs/httpx"
	"github.com/arcgolabs/httpx/adapter"
	"github.com/arcgolabs/dbx"
	adapterfiber "github.com/arcgolabs/httpx/adapter/fiber"
	"github.com/gofiber/fiber/v2"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

func main() {
	rootCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	app := dix.NewDefault(
		// Resolve framework logger from DI so server and migrate share the same path.
		dix.WithLoggerFrom1(func(logger *slog.Logger) *slog.Logger { return logger }),
		dix.WithModules(
			logger.Module(),
			config.Module(),
			authn.Module(),
			kv.Module(),
			httpapi.Module(),
			dix.NewModule("rbac-template",
				dix.Providers(
					dix.ProviderErr2(func(cfg config.Config, logger *slog.Logger) (*DBHandle, error) {
						core, dialect, err := db.Open(rootCtx, cfg.DB, logger)
						if err != nil {
							return nil, err
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
					dix.ProviderErr3(func(cfg config.Config, iamAuthz *application.Authorizer, passwordProvider authx.AuthenticationProvider) (*authx.Engine, error) {
						engine := authx.NewEngine()
						if err := engine.RegisterProvider(
							authjwt.NewAuthenticationProvider(
								authjwt.WithHMACSecret([]byte(cfg.Auth.JWTSecret)),
							),
						); err != nil {
							return nil, err
						}
						if passwordProvider != nil {
							if err := engine.RegisterProvider(passwordProvider); err != nil {
								return nil, err
							}
						}
						engine.SetAuthorizer(authz.NewIAMAuthorizer(iamAuthz))
						return engine, nil
					}),
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
						go func() {
							slog.Default().Info("listening", "addr", cfg.HTTP.Addr, "stack", "httpx/fiber")
								if err := server.ListenAndServeContext(ctx, cfg.HTTP.Addr); err != nil {
									slog.Default().Error("server listen failed", "error", err)
								}
						}()
						return nil
					}),
					dix.OnStop2(func(_ context.Context, server httpx.ServerRuntime, dbh *DBHandle) error {
							if err := server.Shutdown(); err != nil {
								slog.Default().Error("server shutdown failed", "error", err)
							}
						if dbh != nil && dbh.Core != nil {
								if err := dbh.Core.Close(); err != nil {
									slog.Default().Error("db close failed", "error", err)
								}
						}
						return nil
					}),
				),
			),
		),
	)

	if err := app.Validate(); err != nil {
		slog.Default().Error("app validate failed", "error", err)
		return
	}
	if err := app.RunContext(rootCtx); err != nil {
		slog.Default().Error("app run failed", "error", err)
		return
	}
}

type DBHandle struct {
	Core    *dbx.DB
	Dialect db.Dialect
}

