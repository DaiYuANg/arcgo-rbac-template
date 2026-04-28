package httpapi

import (
	"context"

	"github.com/arcgolabs/httpx"
	"github.com/danielgtaylor/huma/v2"
)

type HealthEndpoint struct{}

func (e *HealthEndpoint) EndpointSpec() httpx.EndpointSpec {
	return httpx.EndpointSpec{
		Prefix:        "/api/health",
		Tags:          httpx.Tags("system"),
		SummaryPrefix: "System",
		Description:   "System endpoints",
	}
}

func (e *HealthEndpoint) Register(registrar httpx.Registrar) {
	g := registrar.Scope()
	httpx.MustGroupGet(g, "", func(_ context.Context, _ *struct{}) (*JSONBody[HealthResponse], error) {
		return &JSONBody[HealthResponse]{Body: HealthResponse{State: "UP"}}, nil
	}, func(op *huma.Operation) {
		op.Summary = "Health check"
	})
}
