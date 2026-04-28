package authn

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/arcgolabs/arcgo-rbac-template/internal/config"
	"github.com/arcgolabs/collectionx"
	"github.com/arcgolabs/authx"
	"github.com/arcgolabs/dbx"
	"golang.org/x/crypto/bcrypt"
)

// NewPasswordProvider returns an authx provider that authenticates PasswordCredential
// against enabled sources (root, db).
func NewPasswordProvider(cfg config.Config, core *dbx.DB) authx.AuthenticationProvider {
	return authx.NewAuthenticationProviderFunc[PasswordCredential](func(ctx context.Context, cred PasswordCredential) (authx.AuthenticationResult, error) {
		username := strings.TrimSpace(cred.Username)
		password := cred.Password
		if username == "" || strings.TrimSpace(password) == "" {
			return authx.AuthenticationResult{}, authx.ErrUnauthenticated
		}

		sources := normalizeSources(cfg.Auth.Sources)
		if sources["root"] && checkRoot(cfg, username, password) {
			return authx.AuthenticationResult{
				Principal: authx.Principal{
					ID:    username,
					Roles: collectionx.NewList[string]("admin"),
				},
			}, nil
		}

		if sources["db"] {
			if core == nil {
				return authx.AuthenticationResult{}, errors.New("db auth enabled but database is nil")
			}
			p, ok, err := checkDBUser(ctx, core, username, password)
			if err != nil {
				return authx.AuthenticationResult{}, err
			}
			if ok {
				return authx.AuthenticationResult{Principal: p}, nil
			}
		}

		return authx.AuthenticationResult{}, authx.ErrUnauthenticated
	})
}

func normalizeSources(s string) map[string]bool {
	set := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		key := strings.ToLower(strings.TrimSpace(part))
		if key != "" {
			set[key] = true
		}
	}
	return set
}

func checkRoot(cfg config.Config, username, password string) bool {
	rootUser := strings.TrimSpace(cfg.Auth.RootUsername)
	rootPass := cfg.Auth.RootPassword
	if rootUser == "" || strings.TrimSpace(rootPass) == "" {
		return false
	}
	return username == rootUser && password == rootPass
}

func checkDBUser(ctx context.Context, core *dbx.DB, username, password string) (authx.Principal, bool, error) {
	// roles is stored as comma-separated string.
	if core == nil || core.SQLDB() == nil || core.Dialect() == nil {
		return authx.Principal{}, false, errors.New("db core not ready")
	}
	bind := core.Dialect().BindVar(1)
	q := fmt.Sprintf(`SELECT password_hash, roles FROM auth_users WHERE username = %s`, bind)
	row := core.SQLDB().QueryRowContext(ctx, q, username)
	var hash string
	var roles string
	if err := row.Scan(&hash, &roles); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return authx.Principal{}, false, nil
		}
		return authx.Principal{}, false, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return authx.Principal{}, false, nil
	}

	roleList := collectionx.NewList[string]()
	for _, part := range strings.Split(roles, ",") {
		r := strings.TrimSpace(part)
		if r != "" {
			roleList.Add(r)
		}
	}

	return authx.Principal{
		ID:    username,
		Roles: roleList,
	}, true, nil
}

