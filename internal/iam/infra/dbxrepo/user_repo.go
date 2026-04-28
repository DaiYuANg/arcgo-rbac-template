package dbxrepo

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/arcgolabs/arcgo-rbac-template/internal/db"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/repository"
)

type UserRepo struct {
	core    *dbx.DB
	dialect db.Dialect
	repo    *repository.Base[User, UserSchema]
}

func NewUserRepo(core *dbx.DB, dialect db.Dialect) *UserRepo {
	return &UserRepo{
		core:    core,
		dialect: dialect,
		repo:    repository.New[User](core, Users),
	}
}

func (r *UserRepo) Ensure(ctx context.Context, userID domain.UserID) error {
	id := strings.TrimSpace(string(userID))
	if id == "" {
		return fmt.Errorf("user id is empty")
	}
	return r.repo.Upsert(ctx, &User{ID: id}, "id")
}

func (r *UserRepo) ListRoles(ctx context.Context, userID domain.UserID) ([]domain.RoleID, error) {
	rows, err := r.core.SQLDB().QueryContext(ctx, `SELECT role_id FROM iam_user_roles WHERE user_id = ?`, string(userID))
	if err != nil && r.dialect == db.DialectPostgres {
		rows, err = r.core.SQLDB().QueryContext(ctx, `SELECT role_id FROM iam_user_roles WHERE user_id = $1`, string(userID))
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.RoleID
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, domain.RoleID(v))
	}
	return out, rows.Err()
}

func (r *UserRepo) ListPermissions(ctx context.Context, userID domain.UserID) ([]domain.PermissionID, error) {
	rows, err := r.core.SQLDB().QueryContext(ctx, `SELECT perm_id FROM iam_user_permissions WHERE user_id = ?`, string(userID))
	if err != nil && r.dialect == db.DialectPostgres {
		rows, err = r.core.SQLDB().QueryContext(ctx, `SELECT perm_id FROM iam_user_permissions WHERE user_id = $1`, string(userID))
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.PermissionID
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, domain.PermissionID(v))
	}
	return out, rows.Err()
}

func (r *UserRepo) AssignRole(ctx context.Context, userID domain.UserID, roleID domain.RoleID) error {
	if err := r.Ensure(ctx, userID); err != nil {
		return err
	}
	switch r.dialect {
	case db.DialectMySQL:
		_, err := r.core.SQLDB().ExecContext(ctx, `INSERT IGNORE INTO iam_user_roles (user_id, role_id) VALUES (?, ?)`, string(userID), string(roleID))
		return err
	case db.DialectSQLite:
		_, err := r.core.SQLDB().ExecContext(ctx, `INSERT OR IGNORE INTO iam_user_roles (user_id, role_id) VALUES (?, ?)`, string(userID), string(roleID))
		return err
	case db.DialectPostgres:
		_, err := r.core.SQLDB().ExecContext(ctx, `INSERT INTO iam_user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, string(userID), string(roleID))
		return err
	default:
		return fmt.Errorf("unsupported dialect: %s", r.dialect)
	}
}

func (r *UserRepo) GrantPermission(ctx context.Context, userID domain.UserID, permID domain.PermissionID) error {
	if err := r.Ensure(ctx, userID); err != nil {
		return err
	}
	switch r.dialect {
	case db.DialectMySQL:
		_, err := r.core.SQLDB().ExecContext(ctx, `INSERT IGNORE INTO iam_user_permissions (user_id, perm_id) VALUES (?, ?)`, string(userID), string(permID))
		return err
	case db.DialectSQLite:
		_, err := r.core.SQLDB().ExecContext(ctx, `INSERT OR IGNORE INTO iam_user_permissions (user_id, perm_id) VALUES (?, ?)`, string(userID), string(permID))
		return err
	case db.DialectPostgres:
		_, err := r.core.SQLDB().ExecContext(ctx, `INSERT INTO iam_user_permissions (user_id, perm_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, string(userID), string(permID))
		return err
	default:
		return fmt.Errorf("unsupported dialect: %s", r.dialect)
	}
}

var _ domain.UserRepository = (*UserRepo)(nil)

// Ensure sql import is used when dbx is built without direct sql references.
var _ = sql.ErrNoRows

