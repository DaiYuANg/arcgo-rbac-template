package dbxrepo

import (
	"context"
	"fmt"
	"strings"

	"github.com/arcgolabs/arcgo-rbac-template/internal/db"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/repository"
)

type RoleRepo struct {
	core    *dbx.DB
	dialect db.Dialect
	repo    *repository.Base[Role, RoleSchema]
}

func NewRoleRepo(core *dbx.DB, dialect db.Dialect) *RoleRepo {
	return &RoleRepo{
		core:    core,
		dialect: dialect,
		repo:    repository.New[Role](core, Roles),
	}
}

func (r *RoleRepo) Ensure(ctx context.Context, roleID domain.RoleID) error {
	id := strings.TrimSpace(string(roleID))
	if id == "" {
		return fmt.Errorf("role id is empty")
	}
	return r.repo.Upsert(ctx, &Role{ID: id}, "id")
}

func (r *RoleRepo) ListPermissions(ctx context.Context, roleID domain.RoleID) ([]domain.PermissionID, error) {
	items, err := queryStringColumn(
		ctx,
		r.core,
		r.dialect,
		`SELECT perm_id FROM iam_role_permissions WHERE role_id = ?`,
		`SELECT perm_id FROM iam_role_permissions WHERE role_id = $1`,
		string(roleID),
	)
	if err != nil {
		return nil, err
	}
	out := make([]domain.PermissionID, 0, len(items))
	for _, v := range items {
		out = append(out, domain.PermissionID(v))
	}
	return out, nil
}

func (r *RoleRepo) GrantPermission(ctx context.Context, roleID domain.RoleID, permID domain.PermissionID) error {
	if err := r.Ensure(ctx, roleID); err != nil {
		return err
	}
	switch r.dialect {
	case db.DialectMySQL:
		_, err := r.core.SQLDB().ExecContext(ctx, `INSERT IGNORE INTO iam_role_permissions (role_id, perm_id) VALUES (?, ?)`, string(roleID), string(permID))
		return err
	case db.DialectSQLite:
		_, err := r.core.SQLDB().ExecContext(ctx, `INSERT OR IGNORE INTO iam_role_permissions (role_id, perm_id) VALUES (?, ?)`, string(roleID), string(permID))
		return err
	case db.DialectPostgres:
		_, err := r.core.SQLDB().ExecContext(ctx, `INSERT INTO iam_role_permissions (role_id, perm_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, string(roleID), string(permID))
		return err
	default:
		return fmt.Errorf("unsupported dialect: %s", r.dialect)
	}
}

var _ domain.RoleRepository = (*RoleRepo)(nil)

