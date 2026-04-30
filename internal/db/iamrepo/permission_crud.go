//nolint:dupl // CRUD flows across repos are intentionally parallel.
package iamrepo

import (
	"context"
	"fmt"
	"strings"

	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/column"
	"github.com/arcgolabs/dbx/mapper"
	"github.com/arcgolabs/dbx/paging"
	"github.com/arcgolabs/dbx/querydsl"
	"github.com/arcgolabs/dbx/repository"
)

func (r *PermissionRepo) Get(ctx context.Context, permID domain.PermissionID) (domain.Permission, error) {
	id := strings.TrimSpace(string(permID))
	if id == "" {
		return domain.Permission{}, domain.ErrNotFound
	}
	type row struct {
		ID        string  `dbx:"id"`
		Name      string  `dbx:"name"`
		Code      string  `dbx:"code"`
		CreatedAt int64   `dbx:"created_at"`
		GroupID   *string `dbx:"group_id"`
	}
	joinTable := querydsl.NamedTable("iam_permission_group_permissions")
	joinPermID := column.Named[string](joinTable, "perm_id")
	joinGroupID := column.Named[*string](joinTable, "group_id")
	q := querydsl.Select(Permissions.ID, Permissions.Name, Permissions.Code, Permissions.CreatedAt, joinGroupID.As("group_id")).
		From(Permissions).LeftJoin(joinTable).On(joinPermID.EqColumn(Permissions.ID)).Where(Permissions.ID.Eq(id)).Limit(1)
	first, err := queryOne[row](ctx, r.core, q, "permission get")
	if err != nil {
		return domain.Permission{}, err
	}
	return domain.Permission{ID: domain.PermissionID(first.ID), Name: first.Name, Code: first.Code, CreatedAt: first.CreatedAt}, nil
}

var permissionListOrders = map[string]func(bool) querydsl.Order{
	"id": func(d bool) querydsl.Order {
		if d {
			return Permissions.ID.Desc()
		}
		return Permissions.ID.Asc()
	},
	"name": func(d bool) querydsl.Order {
		if d {
			return Permissions.Name.Desc()
		}
		return Permissions.Name.Asc()
	},
	"code": func(d bool) querydsl.Order {
		if d {
			return Permissions.Code.Desc()
		}
		return Permissions.Code.Asc()
	},
	"createdAt": func(d bool) querydsl.Order {
		if d {
			return Permissions.CreatedAt.Desc()
		}
		return Permissions.CreatedAt.Asc()
	},
}

func permissionListPredicates(q domain.PermissionsListQuery) []querydsl.Predicate {
	preds := make([]querydsl.Predicate, 0, 4)
	if v := strings.TrimSpace(q.NameLike); v != "" {
		preds = append(preds, querydsl.Like(Permissions.Name, "%"+v+"%"))
	}
	if v := strings.TrimSpace(q.CodeLike); v != "" {
		preds = append(preds, querydsl.Like(Permissions.Code, "%"+v+"%"))
	}
	if v := strings.TrimSpace(q.Q); v != "" {
		preds = append(preds, querydsl.Or(querydsl.Like(Permissions.Name, "%"+v+"%"), querydsl.Like(Permissions.Code, "%"+v+"%")))
	}
	return preds
}

func (r *PermissionRepo) List(ctx context.Context, q domain.PermissionsListQuery) (domain.Page[domain.Permission], error) {
	where := predicatesAnd(permissionListPredicates(q))
	desc := q.Order == domain.SortDesc
	ord, oerr := listOrderBy(q.Sort, desc, permissionListOrders)
	if oerr != nil {
		return domain.Page[domain.Permission]{}, fmt.Errorf("permission list: %w", oerr)
	}
	specs := []repository.Spec{repository.OrderBy(ord)}
	if where != nil {
		specs = append(specs, repository.Where(where))
	}
	pageResult, err := r.repo.ListPageSpecRequest(ctx, paging.Request{Page: int(q.Page), PageSize: int(q.PageSize)}, specs...)
	if err != nil {
		return domain.Page[domain.Permission]{}, fmt.Errorf("permission list: %w", err)
	}
	return toDomainPage[Permission, domain.Permission](pageResult, func(ent Permission) domain.Permission {
		return domain.Permission{
			ID:        domain.PermissionID(ent.ID),
			Name:      ent.Name,
			Code:      ent.Code,
			CreatedAt: ent.CreatedAt,
		}
	}), nil
}

func (r *PermissionRepo) Create(ctx context.Context, p domain.Permission) (domain.Permission, error) {
	ent := Permission{ID: strings.TrimSpace(string(p.ID)), Name: strings.TrimSpace(p.Name), Code: strings.TrimSpace(p.Code), CreatedAt: p.CreatedAt}
	if err := repository.New[Permission](r.core, Permissions).Create(ctx, &ent); err != nil {
		return domain.Permission{}, fmt.Errorf("permission create: %w", err)
	}
	return domain.Permission{ID: domain.PermissionID(ent.ID), Name: ent.Name, Code: ent.Code, CreatedAt: ent.CreatedAt}, nil
}

func (r *PermissionRepo) Update(ctx context.Context, p domain.Permission) (domain.Permission, error) {
	id := strings.TrimSpace(string(p.ID))
	if id == "" {
		return domain.Permission{}, domain.ErrNotFound
	}
	upd := querydsl.Update(Permissions).Set(Permissions.Name.Set(strings.TrimSpace(p.Name)), Permissions.Code.Set(strings.TrimSpace(p.Code))).Where(Permissions.ID.Eq(id))
	if _, err := dbx.Exec(ctx, r.core, upd); err != nil {
		return domain.Permission{}, fmt.Errorf("permission update: %w", err)
	}
	return r.Get(ctx, domain.PermissionID(id))
}

func (r *PermissionRepo) Delete(ctx context.Context, permID domain.PermissionID) error {
	id := strings.TrimSpace(string(permID))
	if id == "" {
		return nil
	}
	if _, err := dbx.Exec(ctx, r.core, querydsl.DeleteFrom(PermissionGroupPermissions).Where(PermissionGroupPermissions.PermID.Eq(id))); err != nil {
		return fmt.Errorf("permission delete group links: %w", err)
	}
	if _, err := dbx.Exec(ctx, r.core, querydsl.DeleteFrom(Permissions).Where(Permissions.ID.Eq(id))); err != nil {
		return fmt.Errorf("permission delete: %w", err)
	}
	return nil
}

func (r *PermissionRepo) GetGroupID(ctx context.Context, permID domain.PermissionID) (domain.PermissionGroupID, bool, error) {
	id := strings.TrimSpace(string(permID))
	if id == "" {
		return "", false, nil
	}
	type row struct {
		GroupID string `dbx:"group_id"`
	}
	q := querydsl.Select(PermissionGroupPermissions.GroupID.As("group_id")).From(PermissionGroupPermissions).Where(PermissionGroupPermissions.PermID.Eq(id)).Limit(1)
	items, err := dbx.QueryAll[row](ctx, r.core, q, mapper.MustStructMapper[row]())
	if err != nil {
		return "", false, fmt.Errorf("permission get group: %w", err)
	}
	if items == nil || items.Len() == 0 {
		return "", false, nil
	}
	first, _ := items.Get(0)
	gid := strings.TrimSpace(first.GroupID)
	if gid == "" {
		return "", false, nil
	}
	return domain.PermissionGroupID(gid), true, nil
}

func (r *PermissionRepo) ReplaceGroup(ctx context.Context, permID domain.PermissionID, groupID *domain.PermissionGroupID) error {
	id := strings.TrimSpace(string(permID))
	if id == "" {
		return nil
	}
	return inTx(ctx, r.core, func(tx *dbx.Tx) error {
		if _, err := dbx.Exec(ctx, tx, querydsl.DeleteFrom(PermissionGroupPermissions).Where(PermissionGroupPermissions.PermID.Eq(id))); err != nil {
			return fmt.Errorf("permission replace group delete: %w", err)
		}
		if groupID == nil {
			return nil
		}
		gid := strings.TrimSpace(string(*groupID))
		if gid == "" {
			return nil
		}
		ins := querydsl.InsertInto(PermissionGroupPermissions).Values(PermissionGroupPermissions.GroupID.Set(gid), PermissionGroupPermissions.PermID.Set(id)).OnConflict(PermissionGroupPermissions.GroupID, PermissionGroupPermissions.PermID).DoNothing()
		if _, err := dbx.Exec(ctx, tx, ins); err != nil {
			return fmt.Errorf("permission replace group insert: %w", err)
		}
		return nil
	})
}
