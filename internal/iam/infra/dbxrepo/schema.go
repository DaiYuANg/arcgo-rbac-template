package dbxrepo

import (
	columnx "github.com/arcgolabs/dbx/column"
	"github.com/arcgolabs/dbx/idgen"
	schemax "github.com/arcgolabs/dbx/schema"
)

// --- entities ---

type User struct {
	ID        string `dbx:"id"`
	Email     string `dbx:"email"`
	Name      string `dbx:"name"`
	CreatedAt int64  `dbx:"created_at"`
}

type Role struct {
	ID          string `dbx:"id"`
	Name        string `dbx:"name"`
	Description string `dbx:"description"`
	CreatedAt   int64  `dbx:"created_at"`
}

type Permission struct {
	ID        string `dbx:"id"`
	Name      string `dbx:"name"`
	Code      string `dbx:"code"`
	CreatedAt int64  `dbx:"created_at"`
}

type PermissionGroup struct {
	ID          string `dbx:"id"`
	Name        string `dbx:"name"`
	Description string `dbx:"description"`
	CreatedAt   int64  `dbx:"created_at"`
}

// --- schemas (schema-first) ---

type UserSchema struct {
	schemax.Schema[User]
	ID        columnx.IDColumn[User, string, idgen.IDUUIDv7] `dbx:"id,pk"`
	Email     columnx.Column[User, string] `dbx:"email"`
	Name      columnx.Column[User, string] `dbx:"name"`
	CreatedAt columnx.Column[User, int64]  `dbx:"created_at"`
}

type RoleSchema struct {
	schemax.Schema[Role]
	ID          columnx.IDColumn[Role, string, idgen.IDUUIDv7] `dbx:"id,pk"`
	Name        columnx.Column[Role, string] `dbx:"name"`
	Description columnx.Column[Role, string] `dbx:"description"`
	CreatedAt   columnx.Column[Role, int64]  `dbx:"created_at"`
}

type PermissionSchema struct {
	schemax.Schema[Permission]
	ID        columnx.IDColumn[Permission, string, idgen.IDUUIDv7] `dbx:"id,pk"`
	Name      columnx.Column[Permission, string] `dbx:"name"`
	Code      columnx.Column[Permission, string] `dbx:"code"`
	CreatedAt columnx.Column[Permission, int64]  `dbx:"created_at"`
}

type PermissionGroupSchema struct {
	schemax.Schema[PermissionGroup]
	ID          columnx.IDColumn[PermissionGroup, string, idgen.IDUUIDv7] `dbx:"id,pk"`
	Name        columnx.Column[PermissionGroup, string] `dbx:"name"`
	Description columnx.Column[PermissionGroup, string] `dbx:"description"`
	CreatedAt   columnx.Column[PermissionGroup, int64]  `dbx:"created_at"`
}

var (
	Users            = schemax.MustSchema("iam_users", UserSchema{})
	Roles            = schemax.MustSchema("iam_roles", RoleSchema{})
	Permissions       = schemax.MustSchema("iam_permissions", PermissionSchema{})
	PermissionGroups = schemax.MustSchema("iam_permission_groups", PermissionGroupSchema{})
)

