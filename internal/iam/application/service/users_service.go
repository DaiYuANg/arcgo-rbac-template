package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
)

type UsersService interface {
	List(ctx context.Context, q domain.UsersListQuery) (domain.Page[domain.User], error)
	Get(ctx context.Context, userID domain.UserID) (domain.User, []domain.RoleID, error)
	Create(ctx context.Context, u domain.User, roleIDs []domain.RoleID) (domain.User, []domain.RoleID, error)
	Update(ctx context.Context, u domain.User, roleIDs []domain.RoleID) (domain.User, []domain.RoleID, error)
	Delete(ctx context.Context, userID domain.UserID) error
}

type usersService struct {
	users domain.UserRepository
}

func NewUsersService(users domain.UserRepository) UsersService {
	return &usersService{users: users}
}

func (s *usersService) List(ctx context.Context, q domain.UsersListQuery) (domain.Page[domain.User], error) {
	out, err := s.users.List(ctx, q)
	if err != nil {
		return domain.Page[domain.User]{}, fmt.Errorf("list users: %w", err)
	}
	return out, nil
}

func (s *usersService) Get(ctx context.Context, userID domain.UserID) (domain.User, []domain.RoleID, error) {
	u, err := s.users.Get(ctx, userID)
	if err != nil {
		return domain.User{}, nil, fmt.Errorf("get user: %w", err)
	}
	roleIDs, err := s.users.ListRoles(ctx, userID)
	if err != nil {
		return domain.User{}, nil, fmt.Errorf("list user roles: %w", err)
	}
	return u, roleIDs, nil
}

func (s *usersService) Create(ctx context.Context, u domain.User, roleIDs []domain.RoleID) (domain.User, []domain.RoleID, error) {
	u.Email = strings.TrimSpace(u.Email)
	u.Name = strings.TrimSpace(u.Name)
	created, err := s.users.Create(ctx, u)
	if err != nil {
		return domain.User{}, nil, fmt.Errorf("create user: %w", err)
	}
	if rerr := s.users.ReplaceRoles(ctx, created.ID, roleIDs); rerr != nil {
		return domain.User{}, nil, fmt.Errorf("replace user roles: %w", rerr)
	}
	outRoles, err := s.users.ListRoles(ctx, created.ID)
	if err != nil {
		return domain.User{}, nil, fmt.Errorf("list user roles: %w", err)
	}
	return created, outRoles, nil
}

func (s *usersService) Update(ctx context.Context, u domain.User, roleIDs []domain.RoleID) (domain.User, []domain.RoleID, error) {
	u.Email = strings.TrimSpace(u.Email)
	u.Name = strings.TrimSpace(u.Name)
	updated, err := s.users.Update(ctx, u)
	if err != nil {
		return domain.User{}, nil, fmt.Errorf("update user: %w", err)
	}
	if rerr := s.users.ReplaceRoles(ctx, updated.ID, roleIDs); rerr != nil {
		return domain.User{}, nil, fmt.Errorf("replace user roles: %w", rerr)
	}
	outRoles, err := s.users.ListRoles(ctx, updated.ID)
	if err != nil {
		return domain.User{}, nil, fmt.Errorf("list user roles: %w", err)
	}
	return updated, outRoles, nil
}

func (s *usersService) Delete(ctx context.Context, userID domain.UserID) error {
	if err := s.users.Delete(ctx, userID); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	return nil
}

var _ UsersService = (*usersService)(nil)

