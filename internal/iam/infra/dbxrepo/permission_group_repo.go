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

type PermissionGroupRepo struct {
	core    *dbx.DB
	dialect db.Dialect
	repo    *repository.Base[PermissionGroup, PermissionGroupSchema]
}

func NewPermissionGroupRepo(core *dbx.DB, dialect db.Dialect) *PermissionGroupRepo {
	return &PermissionGroupRepo{
		core:    core,
		dialect: dialect,
		repo:    repository.New[PermissionGroup](core, PermissionGroups),
	}
}

func (r *PermissionGroupRepo) Ensure(ctx context.Context, groupID domain.PermissionGroupID) error {
	id := strings.TrimSpace(string(groupID))
	if id == "" {
		return fmt.Errorf("permission group id is empty")
	}
	return r.repo.Upsert(ctx, &PermissionGroup{ID: id}, "id")
}

func (r *PermissionGroupRepo) ListPermissions(ctx context.Context, groupID domain.PermissionGroupID) ([]domain.PermissionID, error) {
	items, err := queryStringColumn(
		ctx,
		r.core,
		r.dialect,
		`SELECT perm_id FROM iam_permission_group_permissions WHERE group_id = ?`,
		`SELECT perm_id FROM iam_permission_group_permissions WHERE group_id = $1`,
		string(groupID),
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

func (r *PermissionGroupRepo) AddPermission(ctx context.Context, groupID domain.PermissionGroupID, permID domain.PermissionID) error {
	if err := r.Ensure(ctx, groupID); err != nil {
		return err
	}
	switch r.dialect {
	case db.DialectMySQL:
		_, err := r.core.SQLDB().ExecContext(ctx, `INSERT IGNORE INTO iam_permission_group_permissions (group_id, perm_id) VALUES (?, ?)`, string(groupID), string(permID))
		return err
	case db.DialectSQLite:
		_, err := r.core.SQLDB().ExecContext(ctx, `INSERT OR IGNORE INTO iam_permission_group_permissions (group_id, perm_id) VALUES (?, ?)`, string(groupID), string(permID))
		return err
	case db.DialectPostgres:
		_, err := r.core.SQLDB().ExecContext(ctx, `INSERT INTO iam_permission_group_permissions (group_id, perm_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, string(groupID), string(permID))
		return err
	default:
		return fmt.Errorf("unsupported dialect: %s", r.dialect)
	}
}

var _ domain.PermissionGroupRepository = (*PermissionGroupRepo)(nil)

