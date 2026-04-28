// Package kv provides optional distributed cache/client wiring (kvx).
package kv

import (
	"context"
	"log/slog"
	"strings"

	"github.com/DaiYuANg/arcgo/kvx"
	redisadapter "github.com/DaiYuANg/arcgo/kvx/adapter/redis"
	valkeyadapter "github.com/DaiYuANg/arcgo/kvx/adapter/valkey"
	"github.com/arcgolabs/arcgo-rbac-template/internal/config"
	"github.com/arcgolabs/dix"
)

// Module provides an optional kvx.KV (Valkey/Redis via kvx.Client).
func Module() dix.Module {
	return dix.NewModule("kv",
		dix.Providers(
			dix.ProviderErr2(func(cfg config.Config, logger *slog.Logger) (kvx.KV, error) {
				if !cfg.KV.Enabled {
					return nil, nil
				}
				driver := strings.ToLower(strings.TrimSpace(cfg.KV.Driver))
				if driver == "" {
					driver = "valkey"
				}
				opts := kvx.ClientOptions{
					Addrs:    []string{strings.TrimSpace(cfg.KV.Addr)},
					Password: cfg.KV.Password,
					DB:       cfg.KV.DB,
					Logger:   logger,
					Debug:    false,
				}
				switch driver {
				case "valkey":
					return valkeyadapter.New(opts)
				case "redis":
					return redisadapter.New(opts)
				default:
					return nil, context.Canceled
				}
			}),
		),
		dix.Hooks(
			dix.OnStop(func(_ context.Context, k kvx.KV) error {
				if k == nil {
					return nil
				}
				type closer interface {
					Close() error
				}
				if c, ok := k.(closer); ok {
					return c.Close()
				}
				return nil
			}),
		),
	)
}
