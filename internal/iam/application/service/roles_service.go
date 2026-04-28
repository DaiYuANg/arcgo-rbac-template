package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
)

type RolesService interface {
	List(ctx context.Context, q domain.RolesListQuery) (domain.Page[domain.Role], error)
	Get(ctx context.Context, roleID domain.RoleID) (domain.Role, []domain.PermissionGroupID, error)
	Create(ctx context.Context, r domain.Role, groupIDs []domain.PermissionGroupID) (domain.Role, []domain.PermissionGroupID, error)
	Update(ctx context.Context, r domain.Role, groupIDs []domain.PermissionGroupID) (domain.Role, []domain.PermissionGroupID, error)
	Delete(ctx context.Context, roleID domain.RoleID) error
}

type rolesService struct {
	roles domain.RoleRepository
}

func NewRolesService(roles domain.RoleRepository) RolesService {
	return &rolesService{roles: roles}
}

func (s *rolesService) List(ctx context.Context, q domain.RolesListQuery) (domain.Page[domain.Role], error) {
	out, err := s.roles.List(ctx, q)
	if err != nil {
		return domain.Page[domain.Role]{}, fmt.Errorf("list roles: %w", err)
	}
	return out, nil
}

func (s *rolesService) Get(ctx context.Context, roleID domain.RoleID) (domain.Role, []domain.PermissionGroupID, error) {
	r, err := s.roles.Get(ctx, roleID)
	if err != nil {
		return domain.Role{}, nil, fmt.Errorf("get role: %w", err)
	}
	gids, err := s.roles.ListPermissionGroups(ctx, roleID)
	if err != nil {
		return domain.Role{}, nil, fmt.Errorf("list role groups: %w", err)
	}
	return r, gids, nil
}

func (s *rolesService) Create(ctx context.Context, r domain.Role, groupIDs []domain.PermissionGroupID) (domain.Role, []domain.PermissionGroupID, error) {
	r.Name = strings.TrimSpace(r.Name)
	r.Description = strings.TrimSpace(r.Description)
	created, err := s.roles.Create(ctx, r)
	if err != nil {
		return domain.Role{}, nil, fmt.Errorf("create role: %w", err)
	}
	if rerr := s.roles.ReplacePermissionGroups(ctx, created.ID, groupIDs); rerr != nil {
		return domain.Role{}, nil, fmt.Errorf("replace role groups: %w", rerr)
	}
	out, err := s.roles.ListPermissionGroups(ctx, created.ID)
	if err != nil {
		return domain.Role{}, nil, fmt.Errorf("list role groups: %w", err)
	}
	return created, out, nil
}

func (s *rolesService) Update(ctx context.Context, r domain.Role, groupIDs []domain.PermissionGroupID) (domain.Role, []domain.PermissionGroupID, error) {
	r.Name = strings.TrimSpace(r.Name)
	r.Description = strings.TrimSpace(r.Description)
	updated, err := s.roles.Update(ctx, r)
	if err != nil {
		return domain.Role{}, nil, fmt.Errorf("update role: %w", err)
	}
	if rerr := s.roles.ReplacePermissionGroups(ctx, updated.ID, groupIDs); rerr != nil {
		return domain.Role{}, nil, fmt.Errorf("replace role groups: %w", rerr)
	}
	out, err := s.roles.ListPermissionGroups(ctx, updated.ID)
	if err != nil {
		return domain.Role{}, nil, fmt.Errorf("list role groups: %w", err)
	}
	return updated, out, nil
}

func (s *rolesService) Delete(ctx context.Context, roleID domain.RoleID) error {
	if err := s.roles.Delete(ctx, roleID); err != nil {
		return fmt.Errorf("delete role: %w", err)
	}
	return nil
}

var _ RolesService = (*rolesService)(nil)
