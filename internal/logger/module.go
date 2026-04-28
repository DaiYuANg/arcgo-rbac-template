package logger

import (
	"context"
	"log/slog"

	"github.com/arcgolabs/dix"
	"github.com/arcgolabs/logx"
)

// Module provides a process-wide *slog.Logger backed by logx.
// It also sets slog default logger on start and closes logx resources on stop.
func Module() dix.Module {
	return dix.NewModule("logger",
		dix.Providers(
			dix.ProviderErr0(func() (*slog.Logger, error) {
				return logx.New(
					logx.WithConsole(true),
					logx.WithInfoLevel(),
					logx.WithCaller(true),
				)
			}),
		),
		dix.Hooks(
			dix.OnStart(func(_ context.Context, l *slog.Logger) error {
				if l != nil {
					slog.SetDefault(l)
				}
				return nil
			}),
			dix.OnStop(func(_ context.Context, l *slog.Logger) error {
				if l == nil {
					return nil
				}
				return logx.Close(l)
			}),
		),
	)
}

