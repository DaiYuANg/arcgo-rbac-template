package authn

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/arcgolabs/arcgo-rbac-template/internal/config"
	"github.com/arcgolabs/authx"
	"github.com/arcgolabs/collectionx/list"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/mapper"
	"github.com/arcgolabs/dbx/sqlexec"
	"github.com/arcgolabs/dbx/sqlstmt"
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

		out, handled := authenticateRoot(cfg, sources, username, password)
		if handled {
			return out, nil
		}
		return authenticateDBFlow(ctx, sources, cfg, core, username, password)
	})
}

func authenticateRoot(cfg config.Config, sources map[string]bool, username, password string) (authx.AuthenticationResult, bool) {
	if !sources["root"] || !checkRoot(cfg, username, password) {
		return authx.AuthenticationResult{}, false
	}
	return authx.AuthenticationResult{
		Principal: authx.Principal{
			ID:    username,
			Roles: list.NewList[string]("admin"),
		},
	}, true
}

func authenticateDBFlow(
	ctx context.Context,
	sources map[string]bool,
	cfg config.Config,
	core *dbx.DB,
	username, password string,
) (authx.AuthenticationResult, error) {
	_ = cfg
	if !sources["db"] {
		return authx.AuthenticationResult{}, authx.ErrUnauthenticated
	}
	if core == nil {
		return authx.AuthenticationResult{}, errors.New("db auth enabled but database is nil")
	}
	p, ok, err := checkDBUser(ctx, core, username, password)
	if err != nil {
		if errors.Is(err, authx.ErrUnauthenticated) {
			return authx.AuthenticationResult{}, authx.ErrUnauthenticated
		}
		return authx.AuthenticationResult{}, err
	}
	if !ok {
		return authx.AuthenticationResult{}, authx.ErrUnauthenticated
	}
	return authx.AuthenticationResult{Principal: p}, nil
}

func normalizeSources(s string) map[string]bool {
	set := map[string]bool{}
	for part := range strings.SplitSeq(s, ",") {
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
	if core == nil || core.SQLDB() == nil || core.Dialect() == nil {
		return authx.Principal{}, false, errors.New("db core not ready")
	}

	stmt := authUserByUsernameStatement(core)
	result, err := sqlexec.FindTyped[authUserByUsernameParams, authUserByUsernameRow](
		ctx,
		core,
		stmt,
		authUserByUsernameParams{Username: username},
		mapper.MustStructMapper[authUserByUsernameRow](),
	)
	if err != nil {
		return authx.Principal{}, false, fmt.Errorf("query auth_users: %w", err)
	}
	userRow, ok := result.Get()
	if !ok {
		return authx.Principal{}, false, nil
	}

	if bcrypt.CompareHashAndPassword([]byte(userRow.PasswordHash), []byte(password)) != nil {
		return authx.Principal{}, false, authx.ErrUnauthenticated
	}

	roleList := list.NewList[string]()
	for part := range strings.SplitSeq(userRow.Roles, ",") {
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

type authUserByUsernameParams struct {
	Username string
}

type authUserByUsernameRow struct {
	PasswordHash string `dbx:"password_hash"`
	Roles        string `dbx:"roles"`
}

func authUserByUsernameStatement(core *dbx.DB) sqlstmt.TypedSource[authUserByUsernameParams] {
	return sqlstmt.For[authUserByUsernameParams](sqlstmt.New("auth_user_by_username", func(params any) (sqlstmt.Bound, error) {
		p, ok := params.(authUserByUsernameParams)
		if !ok {
			return sqlstmt.Bound{}, errors.New("invalid auth user params")
		}
		bind := core.Dialect().BindVar(1)
		return sqlstmt.Bound{
			Name: "auth_user_by_username",
			SQL:  `SELECT password_hash, roles FROM auth_users WHERE username = ` + bind + ` LIMIT 1`,
			Args: list.NewList[any](p.Username),
		}, nil
	}))
}
