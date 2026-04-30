package iamrepo

import (
	"context"
	"fmt"

	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/querydsl"
)

type RoleRepo struct {
	baseRepo[Role, RoleSchema]
}

func NewRoleRepo(core *dbx.DB) *RoleRepo {
	return &RoleRepo{baseRepo: newBaseRepo[Role](core, Roles)}
}

func (r *RoleRepo) Ensure(ctx context.Context, roleID domain.RoleID) error {
	return ensureStringID(ctx, r.repo, string(roleID), "role", func(id string) *Role { return &Role{ID: id} })
}

func (r *RoleRepo) ListPermissions(ctx context.Context, roleID domain.RoleID) ([]domain.PermissionID, error) {
	q := querydsl.Select(RolePermissions.PermID.As("value")).From(RolePermissions).Where(RolePermissions.RoleID.Eq(string(roleID)))
	items, err := queryStringColumn(ctx, r.core, q)
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
	ins := querydsl.InsertInto(RolePermissions).Values(RolePermissions.RoleID.Set(string(roleID)), RolePermissions.PermID.Set(string(permID))).OnConflict(RolePermissions.RoleID, RolePermissions.PermID).DoNothing()
	_, err := dbx.Exec(ctx, r.core, ins)
	if err != nil {
		return fmt.Errorf("grant permission: %w", err)
	}
	return nil
}

var _ domain.RoleRepository = (*RoleRepo)(nil)
