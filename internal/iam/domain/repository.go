package domain

import "context"

// Keep repos small and entity-focused (DDD-friendly).

type UserRepository interface {
	Ensure(ctx context.Context, userID UserID) error

	ListRoles(ctx context.Context, userID UserID) ([]RoleID, error)
	ListPermissions(ctx context.Context, userID UserID) ([]PermissionID, error)

	AssignRole(ctx context.Context, userID UserID, roleID RoleID) error
	GrantPermission(ctx context.Context, userID UserID, permID PermissionID) error
}

type RoleRepository interface {
	Ensure(ctx context.Context, roleID RoleID) error

	ListPermissions(ctx context.Context, roleID RoleID) ([]PermissionID, error)
	GrantPermission(ctx context.Context, roleID RoleID, permID PermissionID) error
}

type PermissionRepository interface {
	Ensure(ctx context.Context, permID PermissionID) error
}

type PermissionGroupRepository interface {
	Ensure(ctx context.Context, groupID PermissionGroupID) error

	ListPermissions(ctx context.Context, groupID PermissionGroupID) ([]PermissionID, error)
	AddPermission(ctx context.Context, groupID PermissionGroupID, permID PermissionID) error
}

