package dbxrepo

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/repository"
)

type PermissionRepo struct {
	core *dbx.DB
	repo *repository.Base[Permission, PermissionSchema]
}

func NewPermissionRepo(core *dbx.DB) *PermissionRepo {
	return &PermissionRepo{
		core: core,
		repo: repository.New[Permission](core, Permissions),
	}
}

func (r *PermissionRepo) Ensure(ctx context.Context, permID domain.PermissionID) error {
	id := strings.TrimSpace(string(permID))
	if id == "" {
		return errors.New("permission id is empty")
	}
	if err := r.repo.Upsert(ctx, &Permission{ID: id}, "id"); err != nil {
		return fmt.Errorf("permission upsert: %w", err)
	}
	return nil
}

var _ domain.PermissionRepository = (*PermissionRepo)(nil)
