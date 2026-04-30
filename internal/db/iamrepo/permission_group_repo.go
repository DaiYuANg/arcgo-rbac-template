package iamrepo

import (
	"context"
	"fmt"

	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/querydsl"
)

type PermissionGroupRepo struct {
	baseRepo[PermissionGroup, PermissionGroupSchema]
}

func NewPermissionGroupRepo(core *dbx.DB) *PermissionGroupRepo {
	return &PermissionGroupRepo{baseRepo: newBaseRepo[PermissionGroup, PermissionGroupSchema](core, PermissionGroups)}
}

func (r *PermissionGroupRepo) Ensure(ctx context.Context, groupID domain.PermissionGroupID) error {
	return ensureStringID(ctx, r.repo, string(groupID), "permission group", func(id string) *PermissionGroup { return &PermissionGroup{ID: id} })
}

func (r *PermissionGroupRepo) listPermissionIDs(ctx context.Context, groupID string) ([]domain.PermissionID, error) {
	q := querydsl.Select(PermissionGroupPermissions.PermID.As("value")).From(PermissionGroupPermissions).Where(PermissionGroupPermissions.GroupID.Eq(groupID))
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

func (r *PermissionGroupRepo) ListPermissions(ctx context.Context, groupID domain.PermissionGroupID) ([]domain.PermissionID, error) {
	return r.listPermissionIDs(ctx, string(groupID))
}

func (r *PermissionGroupRepo) AddPermission(ctx context.Context, groupID domain.PermissionGroupID, permID domain.PermissionID) error {
	if err := r.Ensure(ctx, groupID); err != nil {
		return err
	}
	ins := r.insertPermission(string(groupID), string(permID))
	_, err := dbx.Exec(ctx, r.core, ins)
	if err != nil {
		return fmt.Errorf("add permission: %w", err)
	}
	return nil
}

func (r *PermissionGroupRepo) insertPermission(groupID, permID string) querydsl.Builder {
	return querydsl.InsertInto(PermissionGroupPermissions).
		Values(PermissionGroupPermissions.GroupID.Set(groupID), PermissionGroupPermissions.PermID.Set(permID)).
		OnConflict(PermissionGroupPermissions.GroupID, PermissionGroupPermissions.PermID).
		DoNothing()
}

var _ domain.PermissionGroupRepository = (*PermissionGroupRepo)(nil)
