package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
)

type PermissionGroupsService interface {
	List(ctx context.Context, q domain.PermissionGroupsListQuery) (domain.Page[domain.PermissionGroup], error)
	Get(ctx context.Context, groupID domain.PermissionGroupID) (domain.PermissionGroup, error)
	Create(ctx context.Context, g domain.PermissionGroup) (domain.PermissionGroup, error)
	Update(ctx context.Context, g domain.PermissionGroup) (domain.PermissionGroup, error)
	Delete(ctx context.Context, groupID domain.PermissionGroupID) error
}

type permissionGroupsService struct {
	groups domain.PermissionGroupRepository
}

func NewPermissionGroupsService(groups domain.PermissionGroupRepository) PermissionGroupsService {
	return &permissionGroupsService{groups: groups}
}

func (s *permissionGroupsService) List(ctx context.Context, q domain.PermissionGroupsListQuery) (domain.Page[domain.PermissionGroup], error) {
	out, err := s.groups.List(ctx, q)
	if err != nil {
		return domain.Page[domain.PermissionGroup]{}, fmt.Errorf("list permission groups: %w", err)
	}
	return out, nil
}

func (s *permissionGroupsService) Get(ctx context.Context, groupID domain.PermissionGroupID) (domain.PermissionGroup, error) {
	out, err := s.groups.Get(ctx, groupID)
	if err != nil {
		return domain.PermissionGroup{}, fmt.Errorf("get permission group: %w", err)
	}
	return out, nil
}

func (s *permissionGroupsService) Create(ctx context.Context, g domain.PermissionGroup) (domain.PermissionGroup, error) {
	g.Name = strings.TrimSpace(g.Name)
	g.Description = strings.TrimSpace(g.Description)
	out, err := s.groups.Create(ctx, g)
	if err != nil {
		return domain.PermissionGroup{}, fmt.Errorf("create permission group: %w", err)
	}
	return out, nil
}

func (s *permissionGroupsService) Update(ctx context.Context, g domain.PermissionGroup) (domain.PermissionGroup, error) {
	g.Name = strings.TrimSpace(g.Name)
	g.Description = strings.TrimSpace(g.Description)
	out, err := s.groups.Update(ctx, g)
	if err != nil {
		return domain.PermissionGroup{}, fmt.Errorf("update permission group: %w", err)
	}
	return out, nil
}

func (s *permissionGroupsService) Delete(ctx context.Context, groupID domain.PermissionGroupID) error {
	if err := s.groups.Delete(ctx, groupID); err != nil {
		return fmt.Errorf("delete permission group: %w", err)
	}
	return nil
}

var _ PermissionGroupsService = (*permissionGroupsService)(nil)
