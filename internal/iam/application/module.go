package application

import (
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/application/service"
	"github.com/arcgolabs/dix"
)

// Module wires IAM application services.
func Module() dix.Module {
	return dix.NewModule("iam.application",
		dix.Providers(
			dix.Provider1(service.NewUsersService),
			dix.Provider1(service.NewRolesService),
			dix.Provider1(service.NewPermissionsService),
			dix.Provider1(service.NewPermissionGroupsService),
			dix.Provider4(service.NewMeService),
		),
	)
}
