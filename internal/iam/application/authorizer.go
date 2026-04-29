// Package application contains IAM/RBAC application services.
package application

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
)

type Decision struct {
	Allowed bool
	Reason  string
}

type Authorizer struct {
	users domain.UserRepository
	roles domain.RoleRepository
}

func NewAuthorizer(users domain.UserRepository, roles domain.RoleRepository) *Authorizer {
	return &Authorizer{users: users, roles: roles}
}

// Can checks whether a user can perform an action (permission) against a resource.
// Resource is currently not used, but is part of the contract for future ABAC/tenancy.
func (a *Authorizer) Can(ctx context.Context, userID domain.UserID, jwtRoles []string, action domain.PermissionID, resource string) (Decision, error) {
	if strings.TrimSpace(string(userID)) == "" {
		return Decision{Allowed: false, Reason: "unauthenticated"}, nil
	}
	if strings.TrimSpace(string(action)) == "" {
		return Decision{Allowed: false, Reason: "missing action"}, nil
	}

	ok, err := a.hasDirectUserPermission(ctx, userID, action)
	if err != nil {
		return Decision{Allowed: false, Reason: "user permissions lookup failed"}, err
	}
	if ok {
		return Decision{Allowed: true, Reason: "user permission"}, nil
	}

	jwtRoleIDs := normalizeRoleIDs(jwtRoles)
	ok, err = a.hasRolePermission(ctx, jwtRoleIDs, action)
	if err != nil {
		return Decision{Allowed: false, Reason: "role permissions lookup failed"}, err
	}
	if ok {
		return Decision{Allowed: true, Reason: "role permission"}, nil
	}

	dbRoleIDs, err := a.listUserRoleIDs(ctx, userID)
	if err != nil {
		return Decision{Allowed: false, Reason: "user roles lookup failed"}, err
	}

	roleIDs := slices.Clone(jwtRoleIDs)
	roleIDs = append(roleIDs, dbRoleIDs...)
	ok, err = a.hasRolePermission(ctx, roleIDs, action)
	if err != nil {
		return Decision{Allowed: false, Reason: "role permissions lookup failed"}, err
	}
	if ok {
		return Decision{Allowed: true, Reason: "role permission"}, nil
	}
	return Decision{Allowed: false, Reason: "denied"}, nil
}

func (a *Authorizer) hasDirectUserPermission(ctx context.Context, userID domain.UserID, action domain.PermissionID) (bool, error) {
	up, err := a.users.ListPermissions(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("list user permissions: %w", err)
	}
	return containsPerm(up, action), nil
}

func normalizeRoleIDs(jwtRoles []string) []domain.RoleID {
	roles := make([]domain.RoleID, 0, len(jwtRoles))
	for _, r := range jwtRoles {
		roleID := domain.RoleID(strings.TrimSpace(r))
		if roleID != "" {
			roles = append(roles, roleID)
		}
	}
	return roles
}

func (a *Authorizer) listUserRoleIDs(ctx context.Context, userID domain.UserID) ([]domain.RoleID, error) {
	sr, err := a.users.ListRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list user roles: %w", err)
	}
	return sr, nil
}

func (a *Authorizer) hasRolePermission(ctx context.Context, roles []domain.RoleID, action domain.PermissionID) (bool, error) {
	seen := map[domain.RoleID]struct{}{}
	for _, role := range roles {
		role = domain.RoleID(strings.TrimSpace(string(role)))
		if role == "" {
			continue
		}
		if _, ok := seen[role]; ok {
			continue
		}
		seen[role] = struct{}{}

		perms, err := a.roles.ListPermissions(ctx, role)
		if err != nil {
			return false, fmt.Errorf("list role permissions: %w", err)
		}
		if containsPerm(perms, action) {
			return true, nil
		}
	}
	return false, nil
}

func containsPerm(xs []domain.PermissionID, want domain.PermissionID) bool {
	return slices.Contains(xs, want)
}
