package application

import (
	"context"
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

	// 1) direct user permissions
	up, err := a.users.ListPermissions(ctx, userID)
	if err != nil {
		return Decision{Allowed: false, Reason: "user permissions lookup failed"}, err
	}
	if containsPerm(up, action) {
		return Decision{Allowed: true, Reason: "user permission"}, nil
	}

	// 2) roles: JWT roles + stored roles
	roles := make([]domain.RoleID, 0, len(jwtRoles)+4)
	for _, r := range jwtRoles {
		r = strings.TrimSpace(r)
		if r != "" {
			roles = append(roles, domain.RoleID(r))
		}
	}

	sr, err := a.users.ListRoles(ctx, userID)
	if err != nil {
		return Decision{Allowed: false, Reason: "user roles lookup failed"}, err
	}
	roles = append(roles, sr...)

	seen := map[domain.RoleID]struct{}{}
	for _, role := range roles {
		if strings.TrimSpace(string(role)) == "" {
			continue
		}
		if _, ok := seen[role]; ok {
			continue
		}
		seen[role] = struct{}{}

		perms, err := a.roles.ListPermissions(ctx, role)
		if err != nil {
			return Decision{Allowed: false, Reason: "role permissions lookup failed"}, err
		}
		if containsPerm(perms, action) {
			return Decision{Allowed: true, Reason: "role permission"}, nil
		}
	}

	return Decision{Allowed: false, Reason: "denied"}, nil
}

func containsPerm(xs []domain.PermissionID, want domain.PermissionID) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

