package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/arcgolabs/arcgo-rbac-template/internal/db"
	"github.com/arcgolabs/arcgo-rbac-template/internal/config"
	"github.com/arcgolabs/arcgo-rbac-template/internal/logger"
	"github.com/arcgolabs/arcgo-rbac-template/internal/migrations"
	dbxmigrate "github.com/arcgolabs/dbx/migrate"
	"github.com/arcgolabs/dix"
)

func main() {
	rootCtx := context.Background()

	app := dix.NewDefault(
		dix.WithLoggerFrom1(func(logger *slog.Logger) *slog.Logger { return logger }),
		dix.WithModules(
			logger.Module(),
			config.Module(),
			dix.NewModule("migrate",
				dix.Hooks(
					dix.OnStart2(func(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
						if cfg.DB.Driver == "memory" {
							logger.Error("migrate requires DB_DRIVER != memory")
							return context.Canceled
						}

						core, dialect, err := db.Open(ctx, cfg.DB, logger)
						if err != nil {
							logger.Error("db open failed", "error", err)
							return err
						}
						defer func() { _ = core.Close() }()

						_ = dialect
						runner := dbxmigrate.NewRunner(core.SQLDB(), core.Dialect(), dbxmigrate.RunnerOptions{
							HistoryTable:    "schema_history",
							AllowOutOfOrder: false,
							ValidateHash:    true,
						})
						mfs, dir := migrations.Filesystem()
						source := dbxmigrate.FileSource{
							FS:  mfs,
							Dir: dir,
						}
						report, err := runner.UpSQL(ctx, source)
						if err != nil {
							logger.Error("migration failed", "error", err)
							return err
						}

						logger.Info("migration completed", "applied", report.Applied.Len())
						return nil
					}),
				),
			),
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

