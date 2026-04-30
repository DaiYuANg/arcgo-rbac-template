package iamrepo

import (
	"context"
	"fmt"

	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/querydsl"
)

type UserRepo struct {
	baseRepo[User, UserSchema]
}

func NewUserRepo(core *dbx.DB) *UserRepo {
	return &UserRepo{
		baseRepo: newBaseRepo[User, UserSchema](core, Users),
	}
}

func (r *UserRepo) Ensure(ctx context.Context, userID domain.UserID) error {
	return ensureStringID(ctx, r.repo, string(userID), "user", func(id string) *User {
		return &User{ID: id}
	})
}

func (r *UserRepo) ListRoles(ctx context.Context, userID domain.UserID) ([]domain.RoleID, error) {
	q := querydsl.Select(UserRoles.RoleID.As("value")).
		From(UserRoles).
		Where(UserRoles.UserID.Eq(string(userID)))
	items, err := queryStringColumn(ctx, r.core, q)
	if err != nil {
		return nil, err
	}
	out := make([]domain.RoleID, 0, len(items))
	for _, v := range items {
		out = append(out, domain.RoleID(v))
	}
	return out, nil
}

func (r *UserRepo) ListPermissions(ctx context.Context, userID domain.UserID) ([]domain.PermissionID, error) {
	q := querydsl.Select(UserPermissions.PermID.As("value")).
		From(UserPermissions).
		Where(UserPermissions.UserID.Eq(string(userID)))
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

func (r *UserRepo) AssignRole(ctx context.Context, userID domain.UserID, roleID domain.RoleID) error {
	if err := r.Ensure(ctx, userID); err != nil {
		return err
	}
	ins := querydsl.
		InsertInto(UserRoles).
		Values(UserRoles.UserID.Set(string(userID)), UserRoles.RoleID.Set(string(roleID))).
		OnConflict(UserRoles.UserID, UserRoles.RoleID).
		DoNothing()
	_, err := dbx.Exec(ctx, r.core, ins)
	if err != nil {
		return fmt.Errorf("assign role: %w", err)
	}
	return nil
}

func (r *UserRepo) GrantPermission(ctx context.Context, userID domain.UserID, permID domain.PermissionID) error {
	if err := r.Ensure(ctx, userID); err != nil {
		return err
	}
	ins := querydsl.
		InsertInto(UserPermissions).
		Values(UserPermissions.UserID.Set(string(userID)), UserPermissions.PermID.Set(string(permID))).
		OnConflict(UserPermissions.UserID, UserPermissions.PermID).
		DoNothing()
	_, err := dbx.Exec(ctx, r.core, ins)
	if err != nil {
		return fmt.Errorf("grant permission: %w", err)
	}
	return nil
}

var _ domain.UserRepository = (*UserRepo)(nil)
