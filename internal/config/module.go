package config

import "github.com/arcgolabs/dix"

// Module provides the typed Config loaded via configx.
func Module() dix.Module {
	return dix.NewModule("config",
		dix.Providers(
			dix.ProviderErr0(Load),
		),
	)
}
