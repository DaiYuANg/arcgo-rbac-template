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
	DialectSQLite   Dialect = "sqlite"
	DialectMySQL    Dialect = "mysql"
	DialectPostgres Dialect = "postgres"
	DialectUnknown  Dialect = "unknown"
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

func sqlDriverAndDialect(dia Dialect) (driver string, d dialect.Dialect, err error) {
	switch dia {
	case DialectPostgres:
		return "pgx", postgres.New(), nil
	case DialectMySQL:
		return "mysql", mysql.New(), nil
	case DialectSQLite:
		return "sqlite", sqlite.New(), nil
	case DialectUnknown:
		return "", nil, fmt.Errorf("unsupported dialect: %q", dia)
	default:
		return "", nil, fmt.Errorf("unsupported dialect: %q", dia)
	}
}

func Open(ctx context.Context, cfg config.DBConfig, logger *slog.Logger) (*dbx.DB, Dialect, error) {
	dia := DialectFromDriver(cfg.Driver)
	if dia == DialectUnknown {
		return nil, DialectUnknown, fmt.Errorf("unsupported DB_DRIVER: %q", cfg.Driver)
	}
	driverName, d, err := sqlDriverAndDialect(dia)
	if err != nil {
		return nil, dia, err
	}

	core, err := dbx.Open(
		dbx.WithDriver(driverName),
		dbx.WithDSN(cfg.DSN),
		dbx.WithDialect(d),
		dbx.ApplyOptions(
			dbx.WithLogger(logger),
		),
	)
	if err != nil {
		return nil, dia, fmt.Errorf("dbx open: %w", err)
	}

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
