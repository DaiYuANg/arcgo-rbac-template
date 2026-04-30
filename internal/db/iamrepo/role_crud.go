//nolint:dupl // CRUD flows across repos are intentionally parallel.
package iamrepo

import (
	"context"
	"fmt"
	"strings"

	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/paging"
	"github.com/arcgolabs/dbx/querydsl"
	"github.com/arcgolabs/dbx/repository"
)

var roleListOrders = map[string]func(bool) querydsl.Order{
	"id": func(d bool) querydsl.Order {
		if d {
			return Roles.ID.Desc()
		}
		return Roles.ID.Asc()
	},
	"name": func(d bool) querydsl.Order {
		if d {
			return Roles.Name.Desc()
		}
		return Roles.Name.Asc()
	},
	"createdAt": func(d bool) querydsl.Order {
		if d {
			return Roles.CreatedAt.Desc()
		}
		return Roles.CreatedAt.Asc()
	},
}

func rolesListPredicates(q domain.RolesListQuery) []querydsl.Predicate {
	preds := make([]querydsl.Predicate, 0, 3)
	if v := strings.TrimSpace(q.NameLike); v != "" {
		preds = append(preds, querydsl.Like(Roles.Name, "%"+v+"%"))
	}
	if v := strings.TrimSpace(q.Q); v != "" {
		preds = append(preds, querydsl.Or(querydsl.Like(Roles.Name, "%"+v+"%"), querydsl.Like(Roles.Description, "%"+v+"%")))
	}
	return preds
}

func (r *RoleRepo) Get(ctx context.Context, roleID domain.RoleID) (domain.Role, error) {
	id := strings.TrimSpace(string(roleID))
	if id == "" {
		return domain.Role{}, domain.ErrNotFound
	}
	type row struct {
		ID          string `dbx:"id"`
		Name        string `dbx:"name"`
		Description string `dbx:"description"`
		CreatedAt   int64  `dbx:"created_at"`
	}
	q := querydsl.Select(Roles.ID, Roles.Name, Roles.Description, Roles.CreatedAt).From(Roles).Where(Roles.ID.Eq(id)).Limit(1)
	first, err := queryOne[row](ctx, r.core, q, "role get")
	if err != nil {
		return domain.Role{}, err
	}
	return domain.Role{ID: domain.RoleID(first.ID), Name: first.Name, Description: first.Description, CreatedAt: first.CreatedAt}, nil
}

func (r *RoleRepo) List(ctx context.Context, q domain.RolesListQuery) (domain.Page[domain.Role], error) {
	where := predicatesAnd(rolesListPredicates(q))
	desc := q.Order == domain.SortDesc
	ord, oerr := listOrderBy(q.Sort, desc, roleListOrders)
	if oerr != nil {
		return domain.Page[domain.Role]{}, fmt.Errorf("role list: %w", oerr)
	}
	specs := []repository.Spec{repository.OrderBy(ord)}
	if where != nil {
		specs = append(specs, repository.Where(where))
	}
	pageResult, err := r.repo.ListPageSpecRequest(ctx, paging.Request{Page: int(q.Page), PageSize: int(q.PageSize)}, specs...)
	if err != nil {
		return domain.Page[domain.Role]{}, fmt.Errorf("role list: %w", err)
	}
	size := 0
	if pageResult.Items != nil {
		size = pageResult.Items.Len()
	}
	out := make([]domain.Role, 0, size)
	if pageResult.Items != nil {
		pageResult.Items.Range(func(_ int, ent Role) bool {
			out = append(out, domain.Role{ID: domain.RoleID(ent.ID), Name: ent.Name, Description: ent.Description, CreatedAt: ent.CreatedAt})
			return true
		})
	}
	return domain.Page[domain.Role]{Items: out, Total: pageResult.Total, Page: int64(pageResult.Page), PageSize: int64(pageResult.PageSize)}, nil
}

func (r *RoleRepo) Create(ctx context.Context, rr domain.Role) (domain.Role, error) {
	ent := Role{ID: strings.TrimSpace(string(rr.ID)), Name: strings.TrimSpace(rr.Name), Description: strings.TrimSpace(rr.Description), CreatedAt: rr.CreatedAt}
	if err := repository.New[Role](r.core, Roles).Create(ctx, &ent); err != nil {
		return domain.Role{}, fmt.Errorf("role create: %w", err)
	}
	return domain.Role{ID: domain.RoleID(ent.ID), Name: ent.Name, Description: ent.Description, CreatedAt: ent.CreatedAt}, nil
}

func (r *RoleRepo) Update(ctx context.Context, rr domain.Role) (domain.Role, error) {
	id := strings.TrimSpace(string(rr.ID))
	if id == "" {
		return domain.Role{}, domain.ErrNotFound
	}
	upd := querydsl.Update(Roles).Set(Roles.Name.Set(strings.TrimSpace(rr.Name)), Roles.Description.Set(strings.TrimSpace(rr.Description))).Where(Roles.ID.Eq(id))
	if _, err := dbx.Exec(ctx, r.core, upd); err != nil {
		return domain.Role{}, fmt.Errorf("role update: %w", err)
	}
	return r.Get(ctx, domain.RoleID(id))
}

func (r *RoleRepo) Delete(ctx context.Context, roleID domain.RoleID) error {
	id := strings.TrimSpace(string(roleID))
	if id == "" {
		return nil
	}
	if _, err := dbx.Exec(ctx, r.core, querydsl.DeleteFrom(UserRoles).Where(UserRoles.RoleID.Eq(id))); err != nil {
		return fmt.Errorf("role delete user links: %w", err)
	}
	if _, err := dbx.Exec(ctx, r.core, querydsl.DeleteFrom(RolePermissionGroups).Where(RolePermissionGroups.RoleID.Eq(id))); err != nil {
		return fmt.Errorf("role delete group links: %w", err)
	}
	if _, err := dbx.Exec(ctx, r.core, querydsl.DeleteFrom(Roles).Where(Roles.ID.Eq(id))); err != nil {
		return fmt.Errorf("role delete: %w", err)
	}
	return nil
}

func (r *RoleRepo) ListPermissionGroups(ctx context.Context, roleID domain.RoleID) ([]domain.PermissionGroupID, error) {
	id := strings.TrimSpace(string(roleID))
	if id == "" {
		return []domain.PermissionGroupID{}, nil
	}
	q := querydsl.Select(RolePermissionGroups.GroupID.As("value")).From(RolePermissionGroups).Where(RolePermissionGroups.RoleID.Eq(id))
	items, err := queryStringColumn(ctx, r.core, q)
	if err != nil {
		return nil, fmt.Errorf("role list groups: %w", err)
	}
	out := make([]domain.PermissionGroupID, 0, len(items))
	for _, v := range items {
		out = append(out, domain.PermissionGroupID(v))
	}
	return out, nil
}

//nolint:gocognit // Explicit transaction steps keep group replacement readable.
func (r *RoleRepo) ReplacePermissionGroups(ctx context.Context, roleID domain.RoleID, groupIDs []domain.PermissionGroupID) error {
	id := strings.TrimSpace(string(roleID))
	if id == "" || groupIDs == nil {
		return nil
	}
	if err := inTx(ctx, r.core, func(tx *dbx.Tx) error {
		if _, err := dbx.Exec(ctx, tx, querydsl.DeleteFrom(RolePermissionGroups).Where(RolePermissionGroups.RoleID.Eq(id))); err != nil {
			return fmt.Errorf("role replace groups delete: %w", err)
		}
		for _, gid := range groupIDs {
			v := strings.TrimSpace(string(gid))
			if v == "" {
				continue
			}
			ins := querydsl.InsertInto(RolePermissionGroups).Values(RolePermissionGroups.RoleID.Set(id), RolePermissionGroups.GroupID.Set(v)).OnConflict(RolePermissionGroups.RoleID, RolePermissionGroups.GroupID).DoNothing()
			if _, err := dbx.Exec(ctx, tx, ins); err != nil {
				return fmt.Errorf("role replace groups insert: %w", err)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}
