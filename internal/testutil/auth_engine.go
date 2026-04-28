// Package testutil provides helpers for integration/unit testing.
package testutil

import (
	"testing"
	"time"

	"github.com/arcgolabs/arcgo-rbac-template/internal/authn"
	"github.com/arcgolabs/arcgo-rbac-template/internal/authz"
	"github.com/arcgolabs/arcgo-rbac-template/internal/config"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/application"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	authjwt "github.com/arcgolabs/authx/jwt"
	"github.com/arcgolabs/authx"
	"github.com/arcgolabs/dbx"
)

// DefaultIntegrationAuth returns auth settings suitable for password + JWT integration tests (SQLite-backed).
func DefaultIntegrationAuth() config.AuthConfig {
	return config.AuthConfig{
		JWTSecret:        "integration-test-secret-must-be-32-characters-min",
		AccessTokenTTL:   time.Hour,
		Issuer:           "integration",
		Audience:         "arcgo",
		AllowInsecureDev: true,
		Sources:          "db",
		RefreshTokenTTL:  time.Hour,
	}
}

// MustAuthEngine builds the same wiring as cmd/server minus HTTP (JWT + DB password + IAM authorizer).
func MustAuthEngine(
	tb testing.TB,
	cfg config.Config,
	core *dbx.DB,
	users domain.UserRepository,
	roles domain.RoleRepository,
) *authx.Engine {
	tb.Helper()
	eng := authx.NewEngine()
	if err := eng.RegisterProvider(
		authjwt.NewAuthenticationProvider(authjwt.WithHMACSecret([]byte(cfg.Auth.JWTSecret))),
	); err != nil {
		tb.Fatalf("register jwt: %v", err)
	}
	if err := eng.RegisterProvider(authn.NewPasswordProvider(cfg, core)); err != nil {
		tb.Fatalf("register password: %v", err)
	}
	iam := application.NewAuthorizer(users, roles)
	eng.SetAuthorizer(authz.NewIAMAuthorizer(iam))
	return eng
}
