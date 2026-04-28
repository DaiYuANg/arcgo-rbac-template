package dbxrepo

import (
	columnx "github.com/arcgolabs/dbx/column"
	schemax "github.com/arcgolabs/dbx/schema"
)

// --- entities ---

type User struct {
	ID string `dbx:"id"`
}

type Role struct {
	ID string `dbx:"id"`
}

type Permission struct {
	ID string `dbx:"id"`
}

type PermissionGroup struct {
	ID string `dbx:"id"`
}

// --- schemas (schema-first) ---

type UserSchema struct {
	schemax.Schema[User]
	ID columnx.Column[User, string] `dbx:"id,pk"`
}

type RoleSchema struct {
	schemax.Schema[Role]
	ID columnx.Column[Role, string] `dbx:"id,pk"`
}

type PermissionSchema struct {
	schemax.Schema[Permission]
	ID columnx.Column[Permission, string] `dbx:"id,pk"`
}

type PermissionGroupSchema struct {
	schemax.Schema[PermissionGroup]
	ID columnx.Column[PermissionGroup, string] `dbx:"id,pk"`
}

var (
	Users            = schemax.MustSchema("iam_users", UserSchema{})
	Roles            = schemax.MustSchema("iam_roles", RoleSchema{})
	Permissions       = schemax.MustSchema("iam_permissions", PermissionSchema{})
	PermissionGroups = schemax.MustSchema("iam_permission_groups", PermissionGroupSchema{})
)

