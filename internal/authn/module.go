package authn

import (
	"github.com/arcgolabs/dix"
)

// Module provides password-based authentication provider(s).
func Module() dix.Module {
	return dix.NewModule("authn",
		dix.Providers(
			dix.Provider2(NewPasswordProvider),
		),
	)
}

