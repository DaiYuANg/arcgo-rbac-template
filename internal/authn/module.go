package authn

import (
	"github.com/arcgolabs/arcgo-rbac-template/internal/config"
	"github.com/arcgolabs/authx"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dix"
)

// Module provides password-based authentication provider(s).
func Module() dix.Module {
	return dix.NewModule("authn",
		dix.Providers(
			dix.Provider2(func(cfg config.Config, core *dbx.DB) authx.AuthenticationProvider {
				return NewPasswordProvider(cfg, core)
			}),
		),
	)
}

