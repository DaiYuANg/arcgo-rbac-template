package dbxrepo

import (
	"context"
	"fmt"
	"strings"

	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/mapper"
	"github.com/arcgolabs/dbx/querydsl"
	"github.com/arcgolabs/dbx/repository"
)

func (r *PermissionGroupRepo) Get(ctx context.Context, groupID domain.PermissionGroupID) (domain.PermissionGroup, error) {
	id := strings.TrimSpace(string(groupID))
	if id == "" {
		return domain.PermissionGroup{}, domain.ErrNotFound
	}
	type row struct {
		ID          string `dbx:"id"`
		Name        string `dbx:"name"`
		Description string `dbx:"description"`
		CreatedAt   int64  `dbx:"created_at"`
	}
	q := querydsl.
		Select(PermissionGroups.ID, PermissionGroups.Name, PermissionGroups.Description, PermissionGroups.CreatedAt).
		From(PermissionGroups).
		Where(PermissionGroups.ID.Eq(id)).
		Limit(1)
	items, err := dbx.QueryAll(ctx, r.core, q, mapper.MustStructMapper[row]())
	if err != nil {
		return domain.PermissionGroup{}, fmt.Errorf("permission group get: %w", err)
	}
	if items == nil || items.Len() == 0 {
		return domain.PermissionGroup{}, domain.ErrNotFound
	}
	first, _ := items.Get(0)
	return domain.PermissionGroup{
		ID:          domain.PermissionGroupID(first.ID),
		Name:        first.Name,
		Description: first.Description,
		CreatedAt:   first.CreatedAt,
	}, nil
}

func (r *PermissionGroupRepo) List(ctx context.Context, q domain.PermissionGroupsListQuery) (domain.Page[domain.PermissionGroup], error) {
	preds := make([]querydsl.Predicate, 0, 3)
	if v := strings.TrimSpace(q.NameLike); v != "" {
		preds = append(preds, querydsl.Like(PermissionGroups.Name, "%"+v+"%"))
	}
	if v := strings.TrimSpace(q.Q); v != "" {
		preds = append(preds, querydsl.Or(
			querydsl.Like(PermissionGroups.Name, "%"+v+"%"),
			querydsl.Like(PermissionGroups.Description, "%"+v+"%"),
		))
	}
	where := querydsl.And(preds...)

	type countRow struct {
		Total int64 `dbx:"total"`
	}
	countQuery := querydsl.
		Select(querydsl.CountAll().As("total")).
		From(PermissionGroups).
		Where(where)
	countItems, err := dbx.QueryAll(ctx, r.core, countQuery, mapper.MustStructMapper[countRow]())
	if err != nil {
		return domain.Page[domain.PermissionGroup]{}, fmt.Errorf("permission group list count: %w", err)
	}
	total := int64(0)
	if countItems != nil && countItems.Len() > 0 {
		first, _ := countItems.Get(0)
		total = first.Total
	}

	type row struct {
		ID          string `dbx:"id"`
		Name        string `dbx:"name"`
		Description string `dbx:"description"`
		CreatedAt   int64  `dbx:"created_at"`
	}
	listQuery := querydsl.
		Select(PermissionGroups.ID, PermissionGroups.Name, PermissionGroups.Description, PermissionGroups.CreatedAt).
		From(PermissionGroups).
		Where(where).
		PageBy(int(q.Page), int(q.PageSize))

	desc := q.Order == domain.SortDesc
	sortKey := strings.TrimSpace(q.Sort)
	if sortKey == "" {
		sortKey = "id"
	}
	orders := map[string]func(bool) querydsl.Order{
		"id": func(d bool) querydsl.Order {
			if d {
				return PermissionGroups.ID.Desc()
			}
			return PermissionGroups.ID.Asc()
		},
		"name": func(d bool) querydsl.Order {
			if d {
				return PermissionGroups.Name.Desc()
			}
			return PermissionGroups.Name.Asc()
		},
		"createdAt": func(d bool) querydsl.Order {
			if d {
				return PermissionGroups.CreatedAt.Desc()
			}
			return PermissionGroups.CreatedAt.Asc()
		},
	}
	orderFn, ok := orders[sortKey]
	if !ok {
		return domain.Page[domain.PermissionGroup]{}, fmt.Errorf("permission group list: invalid sort field: %s", q.Sort)
	}
	listQuery = listQuery.OrderBy(orderFn(desc))

	items, err := dbx.QueryAll(ctx, r.core, listQuery, mapper.MustStructMapper[row]())
	if err != nil {
		return domain.Page[domain.PermissionGroup]{}, fmt.Errorf("permission group list: %w", err)
	}
	out := make([]domain.PermissionGroup, 0, items.Len())
	if items != nil {
		items.Range(func(_ int, r row) bool {
			out = append(out, domain.PermissionGroup{
				ID:          domain.PermissionGroupID(r.ID),
				Name:        r.Name,
				Description: r.Description,
				CreatedAt:   r.CreatedAt,
			})
			return true
		})
	}
	return domain.Page[domain.PermissionGroup]{Items: out, Total: total, Page: q.Page, PageSize: q.PageSize}, nil
}

func (r *PermissionGroupRepo) Create(ctx context.Context, g domain.PermissionGroup) (domain.PermissionGroup, error) {
	ent := PermissionGroup{
		ID:          strings.TrimSpace(string(g.ID)),
		Name:        strings.TrimSpace(g.Name),
		Description: strings.TrimSpace(g.Description),
		CreatedAt:   g.CreatedAt,
	}
	if err := repository.New[PermissionGroup](r.core, PermissionGroups).Create(ctx, &ent); err != nil {
		return domain.PermissionGroup{}, fmt.Errorf("permission group create: %w", err)
	}
	return domain.PermissionGroup{
		ID:          domain.PermissionGroupID(ent.ID),
		Name:        ent.Name,
		Description: ent.Description,
		CreatedAt:   ent.CreatedAt,
	}, nil
}

func (r *PermissionGroupRepo) Update(ctx context.Context, g domain.PermissionGroup) (domain.PermissionGroup, error) {
	id := strings.TrimSpace(string(g.ID))
	if id == "" {
		return domain.PermissionGroup{}, domain.ErrNotFound
	}
	upd := querydsl.
		Update(PermissionGroups).
		Set(
			PermissionGroups.Name.Set(strings.TrimSpace(g.Name)),
			PermissionGroups.Description.Set(strings.TrimSpace(g.Description)),
		).
		Where(PermissionGroups.ID.Eq(id))
	if _, err := dbx.Exec(ctx, r.core, upd); err != nil {
		return domain.PermissionGroup{}, fmt.Errorf("permission group update: %w", err)
	}
	return r.Get(ctx, domain.PermissionGroupID(id))
}

func (r *PermissionGroupRepo) Delete(ctx context.Context, groupID domain.PermissionGroupID) error {
	id := strings.TrimSpace(string(groupID))
	if id == "" {
		return nil
	}
	if _, err := dbx.Exec(ctx, r.core, querydsl.DeleteFrom(RolePermissionGroups).Where(RolePermissionGroups.GroupID.Eq(id))); err != nil {
		return fmt.Errorf("permission group delete role links: %w", err)
	}
	if _, err := dbx.Exec(ctx, r.core, querydsl.DeleteFrom(PermissionGroupPermissions).Where(PermissionGroupPermissions.GroupID.Eq(id))); err != nil {
		return fmt.Errorf("permission group delete perm links: %w", err)
	}
	if _, err := dbx.Exec(ctx, r.core, querydsl.DeleteFrom(PermissionGroups).Where(PermissionGroups.ID.Eq(id))); err != nil {
		return fmt.Errorf("permission group delete: %w", err)
	}
	return nil
}

