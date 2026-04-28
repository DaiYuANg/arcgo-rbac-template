// Package db provides dbx opening helpers and dialect utilities.
package db

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/arcgolabs/arcgo-rbac-template/internal/config"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/dialect"
	"github.com/arcgolabs/dbx/dialect/mysql"
	"github.com/arcgolabs/dbx/dialect/postgres"
	"github.com/arcgolabs/dbx/dialect/sqlite"
)

type Dialect string

const (
	DialectSQLite    Dialect = "sqlite"
	DialectMySQL     Dialect = "mysql"
	DialectPostgres  Dialect = "postgres"
	DialectUnknown   Dialect = "unknown"
)

func DialectFromDriver(driver string) Dialect {
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "sqlite":
		return DialectSQLite
	case "mysql", "mariadb":
		return DialectMySQL
	case "postgres", "postgresql", "pg":
		return DialectPostgres
	default:
		return DialectUnknown
	}
}

func Open(ctx context.Context, cfg config.DBConfig, logger *slog.Logger) (*dbx.DB, Dialect, error) {
	dia := DialectFromDriver(cfg.Driver)
	if dia == DialectUnknown {
		return nil, DialectUnknown, fmt.Errorf("unsupported DB_DRIVER: %q", cfg.Driver)
	}

	driver := strings.ToLower(strings.TrimSpace(cfg.Driver))
	switch dia {
	case DialectPostgres:
		// dbx uses database/sql driver name.
		driver = "pgx"
	case DialectMySQL:
		driver = "mysql"
	case DialectSQLite:
		driver = "sqlite"
	case DialectUnknown:
		return nil, DialectUnknown, fmt.Errorf("unsupported DB_DRIVER: %q", cfg.Driver)
	}

	var d dialect.Dialect
	switch dia {
	case DialectSQLite:
		d = sqlite.New()
	case DialectMySQL:
		d = mysql.New()
	case DialectPostgres:
		d = postgres.New()
	case DialectUnknown:
		return nil, DialectUnknown, fmt.Errorf("unsupported dialect: %q", dia)
	default:
		return nil, DialectUnknown, fmt.Errorf("unsupported dialect: %q", dia)
	}

	core, err := dbx.Open(
		dbx.WithDriver(driver),
		dbx.WithDSN(cfg.DSN),
		dbx.WithDialect(d),
		dbx.ApplyOptions(
			dbx.WithLogger(logger),
		),
	)
	if err != nil {
		return nil, dia, fmt.Errorf("dbx open: %w", err)
	}

	// Ensure the DB is reachable early (dbx.Open already validates configuration; Ping is still useful).
	if ctx != nil {
		if err := core.SQLDB().PingContext(ctx); err != nil {
			if closeErr := core.Close(); closeErr != nil && logger != nil {
				logger.Error("db close failed", "error", closeErr)
			}
			return nil, dia, fmt.Errorf("db ping: %w", err)
		}
	}
	return core, dia, nil
}

