// Package domain contains IAM/RBAC domain types and repository interfaces.
package domain

import "context"

// Keep repos small and entity-focused (DDD-friendly).

type UserRepository interface {
	Ensure(ctx context.Context, userID UserID) error

	Get(ctx context.Context, userID UserID) (User, error)
	List(ctx context.Context, q UsersListQuery) (Page[User], error)
	Create(ctx context.Context, u User) (User, error)
	Update(ctx context.Context, u User) (User, error)
	Delete(ctx context.Context, userID UserID) error

	ListRoles(ctx context.Context, userID UserID) ([]RoleID, error)
	ListPermissions(ctx context.Context, userID UserID) ([]PermissionID, error)

	AssignRole(ctx context.Context, userID UserID, roleID RoleID) error
	GrantPermission(ctx context.Context, userID UserID, permID PermissionID) error

	ReplaceRoles(ctx context.Context, userID UserID, roleIDs []RoleID) error
}

type RoleRepository interface {
	Ensure(ctx context.Context, roleID RoleID) error

	Get(ctx context.Context, roleID RoleID) (Role, error)
	List(ctx context.Context, q RolesListQuery) (Page[Role], error)
	Create(ctx context.Context, r Role) (Role, error)
	Update(ctx context.Context, r Role) (Role, error)
	Delete(ctx context.Context, roleID RoleID) error

	ListPermissions(ctx context.Context, roleID RoleID) ([]PermissionID, error)
	GrantPermission(ctx context.Context, roleID RoleID, permID PermissionID) error

	ListPermissionGroups(ctx context.Context, roleID RoleID) ([]PermissionGroupID, error)
	ReplacePermissionGroups(ctx context.Context, roleID RoleID, groupIDs []PermissionGroupID) error
}

type PermissionRepository interface {
	Ensure(ctx context.Context, permID PermissionID) error

	Get(ctx context.Context, permID PermissionID) (Permission, error)
	List(ctx context.Context, q PermissionsListQuery) (Page[Permission], error)
	Create(ctx context.Context, p Permission) (Permission, error)
	Update(ctx context.Context, p Permission) (Permission, error)
	Delete(ctx context.Context, permID PermissionID) error

	GetGroupID(ctx context.Context, permID PermissionID) (PermissionGroupID, bool, error)
	ReplaceGroup(ctx context.Context, permID PermissionID, groupID *PermissionGroupID) error
}

type PermissionGroupRepository interface {
	Ensure(ctx context.Context, groupID PermissionGroupID) error

	Get(ctx context.Context, groupID PermissionGroupID) (PermissionGroup, error)
	List(ctx context.Context, q PermissionGroupsListQuery) (Page[PermissionGroup], error)
	Create(ctx context.Context, g PermissionGroup) (PermissionGroup, error)
	Update(ctx context.Context, g PermissionGroup) (PermissionGroup, error)
	Delete(ctx context.Context, groupID PermissionGroupID) error

	ListPermissions(ctx context.Context, groupID PermissionGroupID) ([]PermissionID, error)
	AddPermission(ctx context.Context, groupID PermissionGroupID, permID PermissionID) error
}
