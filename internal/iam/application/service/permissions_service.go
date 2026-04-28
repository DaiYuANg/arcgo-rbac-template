package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
)

type PermissionsService interface {
	List(ctx context.Context, q domain.PermissionsListQuery) (domain.Page[domain.Permission], error)
	Get(ctx context.Context, permID domain.PermissionID) (domain.Permission, *domain.PermissionGroupID, error)
	Create(ctx context.Context, p domain.Permission, groupID *domain.PermissionGroupID) (domain.Permission, *domain.PermissionGroupID, error)
	Update(ctx context.Context, p domain.Permission, groupID *domain.PermissionGroupID) (domain.Permission, *domain.PermissionGroupID, error)
	Delete(ctx context.Context, permID domain.PermissionID) error
}

type permissionsService struct {
	perms domain.PermissionRepository
}

func NewPermissionsService(perms domain.PermissionRepository) PermissionsService {
	return &permissionsService{perms: perms}
}

func (s *permissionsService) List(ctx context.Context, q domain.PermissionsListQuery) (domain.Page[domain.Permission], error) {
	out, err := s.perms.List(ctx, q)
	if err != nil {
		return domain.Page[domain.Permission]{}, fmt.Errorf("list permissions: %w", err)
	}
	return out, nil
}

func (s *permissionsService) Get(ctx context.Context, permID domain.PermissionID) (domain.Permission, *domain.PermissionGroupID, error) {
	p, err := s.perms.Get(ctx, permID)
	if err != nil {
		return domain.Permission{}, nil, fmt.Errorf("get permission: %w", err)
	}
	gid, ok, err := s.perms.GetGroupID(ctx, permID)
	if err != nil {
		return domain.Permission{}, nil, fmt.Errorf("permission group lookup: %w", err)
	}
	if !ok {
		return p, nil, nil
	}
	return p, &gid, nil
}

func (s *permissionsService) Create(ctx context.Context, p domain.Permission, groupID *domain.PermissionGroupID) (domain.Permission, *domain.PermissionGroupID, error) {
	p.Name = strings.TrimSpace(p.Name)
	p.Code = strings.TrimSpace(p.Code)
	created, err := s.perms.Create(ctx, p)
	if err != nil {
		return domain.Permission{}, nil, fmt.Errorf("create permission: %w", err)
	}
	if err := s.perms.ReplaceGroup(ctx, created.ID, groupID); err != nil {
		return domain.Permission{}, nil, fmt.Errorf("replace permission group: %w", err)
	}
	out, ok, err := s.perms.GetGroupID(ctx, created.ID)
	if err != nil {
		return domain.Permission{}, nil, fmt.Errorf("permission group lookup: %w", err)
	}
	if !ok {
		return created, nil, nil
	}
	return created, &out, nil
}

func (s *permissionsService) Update(ctx context.Context, p domain.Permission, groupID *domain.PermissionGroupID) (domain.Permission, *domain.PermissionGroupID, error) {
	p.Name = strings.TrimSpace(p.Name)
	p.Code = strings.TrimSpace(p.Code)
	updated, err := s.perms.Update(ctx, p)
	if err != nil {
		return domain.Permission{}, nil, fmt.Errorf("update permission: %w", err)
	}
	if err := s.perms.ReplaceGroup(ctx, updated.ID, groupID); err != nil {
		return domain.Permission{}, nil, fmt.Errorf("replace permission group: %w", err)
	}
	out, ok, err := s.perms.GetGroupID(ctx, updated.ID)
	if err != nil {
		return domain.Permission{}, nil, fmt.Errorf("permission group lookup: %w", err)
	}
	if !ok {
		return updated, nil, nil
	}
	return updated, &out, nil
}

func (s *permissionsService) Delete(ctx context.Context, permID domain.PermissionID) error {
	if err := s.perms.Delete(ctx, permID); err != nil {
		return fmt.Errorf("delete permission: %w", err)
	}
	return nil
}

var _ PermissionsService = (*permissionsService)(nil)

