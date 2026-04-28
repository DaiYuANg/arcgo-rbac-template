package testutil

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/arcgolabs/arcgo-rbac-template/internal/config"
	"github.com/arcgolabs/arcgo-rbac-template/internal/db"
	"github.com/arcgolabs/arcgo-rbac-template/internal/migrations"
	"github.com/arcgolabs/dbx"
	dbxmigrate "github.com/arcgolabs/dbx/migrate"

	// Register modernc SQLite driver for db.Open("sqlite", ...).
	_ "modernc.org/sqlite"
)

// MustMigratingDB opens a file-backed SQLite DB (isolated per test), applies migrations, returns cleanup.
func MustMigratingDB(tb testing.TB) (*dbx.DB, db.Dialect, func()) {
	tb.Helper()
	ctx := context.Background()
	logger := slog.New(slog.DiscardHandler)
	path := filepath.Join(tb.TempDir(), "test.db")
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)", filepath.ToSlash(path))
	core, dialect, err := db.Open(ctx, config.DBConfig{
		Driver: "sqlite",
		DSN:    dsn,
	}, logger)
	if err != nil {
		tb.Fatalf("open db: %v", err)
	}

	runner := dbxmigrate.NewRunner(core.SQLDB(), core.Dialect(), dbxmigrate.RunnerOptions{
		HistoryTable:    "schema_history",
		AllowOutOfOrder: false,
		ValidateHash:    true,
	})
	mfs, dir := migrations.Filesystem()
	if _, err = runner.UpSQL(ctx, dbxmigrate.FileSource{FS: mfs, Dir: dir}); err != nil {
		if closeErr := core.Close(); closeErr != nil {
			tb.Errorf("close db after migrate failure: %v", closeErr)
		}
		tb.Fatalf("migrate: %v", err)
	}

	cleanup := func() {
		if closeErr := core.Close(); closeErr != nil {
			tb.Errorf("close db: %v", closeErr)
		}
	}

	return core, dialect, cleanup
}
