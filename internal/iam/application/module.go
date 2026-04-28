package application

import (
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/application/service"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/dix"
)

// Module wires IAM application services.
func Module() dix.Module {
	return dix.NewModule("iam.application",
		dix.Providers(
			dix.Provider1(func(users domain.UserRepository) service.UsersService {
				return service.NewUsersService(users)
			}),
			dix.Provider1(func(roles domain.RoleRepository) service.RolesService {
				return service.NewRolesService(roles)
			}),
			dix.Provider1(func(perms domain.PermissionRepository) service.PermissionsService {
				return service.NewPermissionsService(perms)
			}),
			dix.Provider1(func(groups domain.PermissionGroupRepository) service.PermissionGroupsService {
				return service.NewPermissionGroupsService(groups)
			}),
			dix.Provider4(func(
				users domain.UserRepository,
				roles domain.RoleRepository,
				groups domain.PermissionGroupRepository,
				perms domain.PermissionRepository,
			) service.MeService {
				return service.NewMeService(users, roles, groups, perms)
			}),
		),
	)
}

