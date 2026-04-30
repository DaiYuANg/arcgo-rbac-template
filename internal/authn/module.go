package authn

import (
	"fmt"

	"github.com/arcgolabs/arcgo-rbac-template/internal/authz"
	"github.com/arcgolabs/arcgo-rbac-template/internal/config"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/application"
	"github.com/arcgolabs/authx"
	authjwt "github.com/arcgolabs/authx/jwt"
	"github.com/arcgolabs/dix"
)

// Module provides password-based authentication provider(s).
func Module() dix.Module {
	return dix.NewModule("authn",
		dix.Providers(
			dix.Provider2(NewPasswordProvider),
			dix.ProviderErr3(newAuthEngine),
		),
	)
}

func newAuthEngine(cfg config.Config, iamAuthz *application.Authorizer, passwordProvider authx.AuthenticationProvider) (*authx.Engine, error) {
	engine := authx.NewEngine()
	if err := engine.RegisterProvider(
		authjwt.NewAuthenticationProvider(
			authjwt.WithHMACSecret([]byte(cfg.Auth.JWTSecret)),
		),
	); err != nil {
		return nil, fmt.Errorf("register jwt provider: %w", err)
	}
	if passwordProvider != nil {
		if err := engine.RegisterProvider(passwordProvider); err != nil {
			return nil, fmt.Errorf("register password provider: %w", err)
		}
	}
	engine.SetAuthorizer(authz.NewIAMAuthorizer(iamAuthz))
	return engine, nil
}
