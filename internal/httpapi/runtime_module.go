package httpapi

import (
	"context"
	"fmt"
	"log/slog"
	"sort"

	"github.com/arcgolabs/arcgo-rbac-template/internal/config"
	"github.com/arcgolabs/httpx"
	"github.com/arcgolabs/httpx/adapter"
	adapterfiber "github.com/arcgolabs/httpx/adapter/fiber"
	"github.com/gofiber/fiber/v2"
)

func runHTTPServer(ctx context.Context, cfg config.Config, server httpx.ServerRuntime) {
	slog.Default().Info("listening", "addr", cfg.HTTP.Addr, "stack", "httpx/fiber")
	if err := server.ListenAndServeContext(ctx, cfg.HTTP.Addr); err != nil {
		slog.Default().Error("server listen failed", "error", err)
	}
}

func shutdownServer(server httpx.ServerRuntime) error {
	if server == nil {
		return nil
	}
	if err := server.Shutdown(); err != nil {
		return fmt.Errorf("shutdown server: %w", err)
	}
	return nil
}

func logRouteSummary(server httpx.ServerRuntime, logger *slog.Logger) {
	if server == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}

	total := server.RouteCount()
	authRoutes := server.GetRoutesByPath("/api/auth")
	methodGroups := server.GetRoutesGroupedByMethod()

	methodCounts := map[string]int{}
	if methodGroups != nil {
		methodGroups.Range(func(method string, routes []httpx.RouteInfo) bool {
			methodCounts[method] = len(routes)
			return true
		})
	}

	methods := make([]string, 0, len(methodCounts))
	for method := range methodCounts {
		methods = append(methods, method)
	}
	sort.Strings(methods)
	orderedCounts := make([]string, 0, len(methods))
	for _, method := range methods {
		orderedCounts = append(orderedCounts, fmt.Sprintf("%s:%d", method, methodCounts[method]))
	}

	logger.Info("http routes ready",
		"total", total,
		"auth_routes", authRoutes.Len(),
		"methods", orderedCounts,
	)
}

func newAdapter(app *fiber.App) *adapterfiber.Adapter {
	return adapterfiber.New(app, adapter.HumaOptions{
		Title:       "arcgo-rbac-template",
		Version:     "0.1.0",
		Description: "RBAC template (authx + httpx + dix + dbx + configx)",
		DocsPath:    "/docs",
		OpenAPIPath: "/openapi.json",
	})
}
