// Command migrate applies embedded SQL migrations to the configured database.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/arcgolabs/arcgo-rbac-template/internal/config"
	"github.com/arcgolabs/arcgo-rbac-template/internal/db"
	"github.com/arcgolabs/arcgo-rbac-template/internal/logger"
	"github.com/arcgolabs/arcgo-rbac-template/internal/migrations"
	"github.com/arcgolabs/dix"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

func main() {
	rootCtx := context.Background()

	app := dix.NewDefault(
		dix.WithLoggerFrom1(func(logger *slog.Logger) *slog.Logger { return logger }),
		dix.WithModules(
			logger.Module(),
			config.Module(),
			db.Module(),
			migrations.Module(),
		),
	)

	if err := app.Validate(); err != nil {
		slog.Default().Error("app validate failed", "error", err)
		os.Exit(1)
	}

	rt, err := app.Start(rootCtx)
	if err != nil {
		slog.Default().Error("app start failed", "error", err)
		os.Exit(1)
	}
	if err := rt.Stop(context.Background()); err != nil {
		slog.Default().Error("app stop failed", "error", err)
		os.Exit(1)
	}
}
