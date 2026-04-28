package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
)

type RoleRef struct {
	ID   domain.RoleID
	Name string
}

type MeInfo struct {
	UserID      domain.UserID
	Name        string
	Email       string
	Roles       []RoleRef
	Permissions []string
}

type MeService interface {
	GetMe(ctx context.Context, userID domain.UserID, jwtRoles []domain.RoleID) (MeInfo, error)
}

type meService struct {
	users  domain.UserRepository
	roles  domain.RoleRepository
	groups domain.PermissionGroupRepository
	perms  domain.PermissionRepository
}

func NewMeService(
	users domain.UserRepository,
	roles domain.RoleRepository,
	groups domain.PermissionGroupRepository,
	perms domain.PermissionRepository,
) MeService {
	return &meService{users: users, roles: roles, groups: groups, perms: perms}
}

func (s *meService) GetMe(ctx context.Context, userID domain.UserID, jwtRoles []domain.RoleID) (MeInfo, error) {
	u, err := s.users.Get(ctx, userID)
	if err != nil {
		return MeInfo{}, fmt.Errorf("get user: %w", err)
	}

	roleRefs, err := s.resolveRoleRefs(ctx, userID, jwtRoles)
	if err != nil {
		return MeInfo{}, err
	}
	if info := meInfoIfAdminShortcut(userID, u, roleRefs); info != nil {
		return *info, nil
	}

	perms := s.collectPermissionsForRoles(ctx, roleRefs)
	return MeInfo{
		UserID:      userID,
		Name:        u.Name,
		Email:       u.Email,
		Roles:       roleRefs,
		Permissions: perms,
	}, nil
}

func mergeRoleIDs(jwtRoles, dbRoles []domain.RoleID) []domain.RoleID {
	roleIDs := make([]domain.RoleID, 0, len(jwtRoles)+len(dbRoles)+8)
	roleIDs = append(roleIDs, jwtRoles...)
	roleIDs = append(roleIDs, dbRoles...)
	return roleIDs
}

func (s *meService) resolveRoleRefs(ctx context.Context, userID domain.UserID, jwtRoles []domain.RoleID) ([]RoleRef, error) {
	dbRoles, err := s.users.ListRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list user roles: %w", err)
	}
	allIDs := mergeRoleIDs(jwtRoles, dbRoles)

	seenRole := map[domain.RoleID]struct{}{}
	roleRefs := make([]RoleRef, 0, len(allIDs))
	for _, rid := range allIDs {
		rid = domain.RoleID(strings.TrimSpace(string(rid)))
		if rid == "" {
			continue
		}
		if _, ok := seenRole[rid]; ok {
			continue
		}
		seenRole[rid] = struct{}{}

		r, rerr := s.roles.Get(ctx, rid)
		if rerr != nil {
			roleRefs = append(roleRefs, RoleRef{ID: rid, Name: string(rid)})
			continue
		}
		name := strings.TrimSpace(r.Name)
		if name == "" {
			name = string(rid)
		}
		roleRefs = append(roleRefs, RoleRef{ID: rid, Name: name})
	}
	return roleRefs, nil
}

func meInfoIfAdminShortcut(userID domain.UserID, u domain.User, roleRefs []RoleRef) *MeInfo {
	for _, rr := range roleRefs {
		if rr.Name == "admin" || rr.Name == "管理员" {
			return &MeInfo{
				UserID: userID,
				Name:   u.Name,
				Email:  u.Email,
				Roles:  roleRefs,
				Permissions: []string{
					"users:read", "users:write",
					"roles:read", "roles:write",
					"permissions:read", "permissions:write",
					"permission-groups:read", "permission-groups:write",
				},
			}
		}
	}
	return nil
}

func (s *meService) collectPermissionsForRoles(ctx context.Context, roleRefs []RoleRef) []string {
	seenPerm := map[string]struct{}{}
	outPerms := []string{}

	for _, rr := range roleRefs {
		s.appendPermCodesForRole(ctx, rr, seenPerm, &outPerms)
	}

	return outPerms
}

func (s *meService) appendPermCodesForRole(ctx context.Context, rr RoleRef, seenPerm map[string]struct{}, outPerms *[]string) {
	gids, gerr := s.roles.ListPermissionGroups(ctx, rr.ID)
	if gerr != nil {
		return
	}
	for _, gid := range gids {
		s.appendPermCodesForGroup(ctx, gid, seenPerm, outPerms)
	}
}

func (s *meService) appendPermCodesForGroup(ctx context.Context, gid domain.PermissionGroupID, seenPerm map[string]struct{}, outPerms *[]string) {
	pids, perr := s.groups.ListPermissions(ctx, gid)
	if perr != nil {
		return
	}
	for _, pid := range pids {
		p, perr := s.perms.Get(ctx, pid)
		if perr != nil {
			continue
		}
		code := strings.TrimSpace(p.Code)
		if code == "" {
			continue
		}
		if _, ok := seenPerm[code]; ok {
			continue
		}
		seenPerm[code] = struct{}{}
		*outPerms = append(*outPerms, code)
	}
}

var _ MeService = (*meService)(nil)
