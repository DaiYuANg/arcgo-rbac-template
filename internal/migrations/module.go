package migrations

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/arcgolabs/arcgo-rbac-template/internal/config"
	"github.com/arcgolabs/arcgo-rbac-template/internal/db"
	dbxmigrate "github.com/arcgolabs/dbx/migrate"
	"github.com/arcgolabs/dix"
)

// Module runs embedded SQL migrations during app start.
func Module() dix.Module {
	return dix.NewModule("migrations",
		dix.Hooks(
			dix.OnStart3(func(ctx context.Context, cfg config.Config, logger *slog.Logger, h *db.Handle) error {
				if cfg.DB.Driver == "memory" {
					logger.Error("migrate requires DB_DRIVER != memory")
					return context.Canceled
				}
				if h == nil || h.Core == nil {
					return errors.New("db handle unavailable")
				}

				runner := dbxmigrate.NewRunner(h.Core.SQLDB(), h.Core.Dialect(), dbxmigrate.RunnerOptions{
					HistoryTable:    "schema_history",
					AllowOutOfOrder: false,
					ValidateHash:    true,
				})
				mfs, dir := Filesystem()
				source := dbxmigrate.FileSource{
					FS:  mfs,
					Dir: dir,
				}
				report, err := runner.UpSQL(ctx, source)
				if err != nil {
					logger.Error("migration failed", "error", err)
					return fmt.Errorf("migration up: %w", err)
				}

				logger.Info("migration completed", "applied", report.Applied.Len())
				return nil
			}),
		),
	)
}
