package db

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/arcgolabs/arcgo-rbac-template/internal/config"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dix"
)

// Handle is the opened database runtime handle used by downstream modules.
type Handle struct {
	Core    *dbx.DB
	Dialect Dialect
}

// Module wires db opening/closing and exposes *dbx.DB.
func Module() dix.Module {
	return dix.NewModule("db",
		dix.Providers(
			dix.ProviderErr2(func(cfg config.Config, logger *slog.Logger) (*Handle, error) {
				core, dialect, err := Open(context.Background(), cfg.DB, logger)
				if err != nil {
					return nil, fmt.Errorf("db open: %w", err)
				}
				return &Handle{Core: core, Dialect: dialect}, nil
			}),
			dix.Provider1(func(h *Handle) *dbx.DB {
				if h == nil {
					return nil
				}
				return h.Core
			}),
		),
		dix.Hooks(
			dix.OnStop(func(_ context.Context, h *Handle) error {
				if h == nil || h.Core == nil {
					return nil
				}
				return h.Core.Close()
			}),
		),
	)
}
