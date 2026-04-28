package dbxrepo

import (
	"context"
	"fmt"
	"strings"

	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/repository"
)

type PermissionRepo struct {
	repo *repository.Base[Permission, PermissionSchema]
}

func NewPermissionRepo(core *dbx.DB) *PermissionRepo {
	return &PermissionRepo{
		repo: repository.New[Permission](core, Permissions),
	}
}

func (r *PermissionRepo) Ensure(ctx context.Context, permID domain.PermissionID) error {
	id := strings.TrimSpace(string(permID))
	if id == "" {
		return fmt.Errorf("permission id is empty")
	}
	return r.repo.Upsert(ctx, &Permission{ID: id}, "id")
}

var _ domain.PermissionRepository = (*PermissionRepo)(nil)

