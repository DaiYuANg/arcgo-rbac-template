// Command server starts the HTTP API server.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/arcgolabs/arcgo-rbac-template/internal/authn"
	"github.com/arcgolabs/arcgo-rbac-template/internal/config"
	"github.com/arcgolabs/arcgo-rbac-template/internal/db"
	"github.com/arcgolabs/arcgo-rbac-template/internal/db/iamrepo"
	"github.com/arcgolabs/arcgo-rbac-template/internal/httpapi"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/application"
	"github.com/arcgolabs/arcgo-rbac-template/internal/kv"
	"github.com/arcgolabs/arcgo-rbac-template/internal/logger"
	"github.com/arcgolabs/dix"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

func main() {
	rootCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	app := dix.NewDefault(
		dix.WithLoggerFrom1(func(logger *slog.Logger) *slog.Logger { return logger }),
		dix.WithModules(
			logger.Module(),
			config.Module(),
			db.Module(),
			iamrepo.Module(),
			authn.Module(),
			kv.Module(),
			application.Module(),
			httpapi.Module(),
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
