package iamrepo

import (
	"context"

	"github.com/arcgolabs/arcgo-rbac-template/internal/db"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/dix"
)

// Module wires dbx-backed IAM repositories.
//
//nolint:gocognit // Provider wiring is intentionally explicit per repository.
func Module() dix.Module {
	return dix.NewModule("iam.dbxrepo",
		dix.Providers(
			dix.ProviderErr1(func(h *db.Handle) (domain.UserRepository, error) {
				if h == nil || h.Core == nil {
					return nil, context.Canceled
				}
				return NewUserRepo(h.Core), nil
			}),
			dix.ProviderErr1(func(h *db.Handle) (domain.RoleRepository, error) {
				if h == nil || h.Core == nil {
					return nil, context.Canceled
				}
				return NewRoleRepo(h.Core), nil
			}),
			dix.ProviderErr1(func(h *db.Handle) (domain.PermissionRepository, error) {
				if h == nil || h.Core == nil {
					return nil, context.Canceled
				}
				return NewPermissionRepo(h.Core), nil
			}),
			dix.ProviderErr1(func(h *db.Handle) (domain.PermissionGroupRepository, error) {
				if h == nil || h.Core == nil {
					return nil, context.Canceled
				}
				return NewPermissionGroupRepo(h.Core), nil
			}),
		),
	)
}
