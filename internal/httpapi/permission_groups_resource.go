package httpapi

import (
	"context"
	"fmt"
	"strings"

	"github.com/arcgolabs/authx"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/mapper"
	"github.com/arcgolabs/dbx/querydsl"
	"github.com/arcgolabs/httpx"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/infra/dbxrepo"
)

type PermissionGroupsResource struct {
	engine *authx.Engine
	core   *dbx.DB
}

func (e *PermissionGroupsResource) FiberBinding() FiberBinding {
	return FiberBinding{
		Prefix:  "/api/permission-groups",
		Handler: requirePermissionFiber(e.engine, "permission-groups:read", "/permission-groups"),
	}
}

func (e *PermissionGroupsResource) EndpointSpec() httpx.EndpointSpec {
	return httpx.EndpointSpec{
		Prefix:        "/api/permission-groups",
		Tags:          httpx.Tags("permission-groups"),
		SummaryPrefix: "Permission Groups",
		Description:   "Permission groups resource",
	}
}

type pgListInput struct {
	ID       string `query:"id"`
	Page     int64  `query:"page"`
	PageSize int64  `query:"pageSize"`
	Q        string `query:"q"`
	Sort     string `query:"sort"`
	Order    string `query:"order"`
	NameLike string `query:"name_like"`
}

func (e *PermissionGroupsResource) Register(registrar httpx.Registrar) {
	g := registrar.Scope()
	httpx.MustAuto(g,
		httpx.Auto(e.ListOrGetMany),
		httpx.Auto(e.GetByID),
		httpx.Auto(e.Create),
		httpx.Auto(e.UpdateByID),
		httpx.Auto(e.DeleteByID),
	)
	httpx.MustGroupPost(g, "/bulk", e.CreateMany)
	httpx.MustGroupPatch(g, "/bulk", e.UpdateMany)
	httpx.MustGroupDelete(g, "", e.DeleteMany)
}

func (e *PermissionGroupsResource) ListOrGetMany(ctx context.Context, in *pgListInput) (*PageResponse[PermissionGroupDTO], error) {
	if strings.TrimSpace(in.ID) != "" {
		items := []PermissionGroupDTO{}
		for _, id := range splitIDs(in.ID) {
			item, err := e.Get(ctx, &userIDPath{ID: id})
			if err == nil && item != nil {
				items = append(items, *item)
			}
		}
		pageSize := int64(len(items))
		return &PageResponse[PermissionGroupDTO]{Items: items, Total: pageSize, Page: 1, PageSize: pageSize}, nil
	}
	return e.List(ctx, in)
}

func (e *PermissionGroupsResource) List(ctx context.Context, in *pgListInput) (*PageResponse[PermissionGroupDTO], error) {
	if e.core == nil {
		return nil, httpx.NewError(500, "db_missing")
	}
	if in.Page <= 0 || in.PageSize <= 0 {
		return nil, httpx.NewError(400, "validation", fmt.Errorf("page and pageSize are required"))
	}

	type countRow struct {
		Total int64 `dbx:"total"`
	}
	type pgRow struct {
		ID          string `dbx:"id"`
		Name        string `dbx:"name"`
		Description string `dbx:"description"`
		CreatedAt   int64  `dbx:"created_at"`
	}

	predicates := make([]querydsl.Predicate, 0, 3)
	if v := strings.TrimSpace(in.NameLike); v != "" {
		predicates = append(predicates, querydsl.Like(dbxrepo.PermissionGroups.Name, "%"+v+"%"))
	}
	if v := strings.TrimSpace(in.Q); v != "" {
		predicates = append(predicates, querydsl.Or(
			querydsl.Like(dbxrepo.PermissionGroups.Name, "%"+v+"%"),
			querydsl.Like(dbxrepo.PermissionGroups.Description, "%"+v+"%"),
		))
	}
	where := querydsl.And(predicates...)

	countQuery := querydsl.
		Select(querydsl.CountAll().As("total")).
		From(dbxrepo.PermissionGroups).
		Where(where)
	countItems, err := dbx.QueryAll(ctx, e.core, countQuery, mapper.MustStructMapper[countRow]())
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	total := int64(0)
	if countItems != nil && countItems.Len() > 0 {
		first, _ := countItems.Get(0)
		total = first.Total
	}

	listQuery := querydsl.
		Select(dbxrepo.PermissionGroups.ID, dbxrepo.PermissionGroups.Name, dbxrepo.PermissionGroups.Description, dbxrepo.PermissionGroups.CreatedAt).
		From(dbxrepo.PermissionGroups).
		Where(where).
		PageBy(int(in.Page), int(in.PageSize))

	sort := strings.TrimSpace(in.Sort)
	order := strings.ToLower(strings.TrimSpace(in.Order))
	if order == "" {
		order = "asc"
	}
	desc := order == "desc"
	if sort != "" {
		var ord querydsl.Order
		switch sort {
		case "id":
			if desc {
				ord = dbxrepo.PermissionGroups.ID.Desc()
			} else {
				ord = dbxrepo.PermissionGroups.ID.Asc()
			}
		case "name":
			if desc {
				ord = dbxrepo.PermissionGroups.Name.Desc()
			} else {
				ord = dbxrepo.PermissionGroups.Name.Asc()
			}
		case "createdAt":
			if desc {
				ord = dbxrepo.PermissionGroups.CreatedAt.Desc()
			} else {
				ord = dbxrepo.PermissionGroups.CreatedAt.Asc()
			}
		default:
			return nil, httpx.NewError(400, "validation", fmt.Errorf("invalid sort field: %s", sort))
		}
		listQuery = listQuery.OrderBy(ord)
	}

	rows, err := dbx.QueryAll(ctx, e.core, listQuery, mapper.MustStructMapper[pgRow]())
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	items := make([]PermissionGroupDTO, 0, int(in.PageSize))
	if rows != nil {
		rows.Range(func(_ int, r pgRow) bool {
			items = append(items, PermissionGroupDTO{
				ID:          r.ID,
				Name:        r.Name,
				Description: r.Description,
				CreatedAt:   unixMilliToRFC3339(r.CreatedAt),
			})
			return true
		})
	}

	return &PageResponse[PermissionGroupDTO]{Items: items, Total: total, Page: in.Page, PageSize: in.PageSize}, nil
}

func (e *PermissionGroupsResource) Get(ctx context.Context, in *userIDPath) (*PermissionGroupDTO, error) {
	if e.core == nil {
		return nil, httpx.NewError(500, "db_missing")
	}
	id := strings.TrimSpace(in.ID)
	q := fmt.Sprintf("SELECT id, name, description, created_at FROM iam_permission_groups WHERE id=%s", bind(e.core, 1))
	row := e.core.SQLDB().QueryRowContext(ctx, q, id)
	var name, desc string
	var createdAt int64
	if err := row.Scan(&id, &name, &desc, &createdAt); err != nil {
		return nil, httpx.NewError(404, "not_found", err)
	}
	return &PermissionGroupDTO{ID: id, Name: name, Description: desc, CreatedAt: unixMilliToRFC3339(createdAt)}, nil
}

func (e *PermissionGroupsResource) GetByID(ctx context.Context, in *userIDPath) (*PermissionGroupDTO, error) {
	return e.Get(ctx, in)
}

type createPGInput struct{ Body PermissionGroupDTO `json:"body"` }

func (e *PermissionGroupsResource) Create(ctx context.Context, in *createPGInput) (*PermissionGroupDTO, error) {
	if e.core == nil {
		return nil, httpx.NewError(500, "db_missing")
	}
	if err := enforce(ctx, e.engine, "permission-groups:write", "/permission-groups"); err != nil {
		return nil, err
	}
	pg := in.Body
	pg.ID = strings.TrimSpace(pg.ID)
	pg.Name = strings.TrimSpace(pg.Name)
	desc := strings.TrimSpace(pg.Description)
	if pg.ID == "" || pg.Name == "" {
		return nil, httpx.NewError(422, "validation")
	}
	now := nowUnixMilli()
	q := fmt.Sprintf("INSERT INTO iam_permission_groups (id, name, description, created_at) VALUES (%s,%s,%s,%s)", bind(e.core, 1), bind(e.core, 2), bind(e.core, 3), bind(e.core, 4))
	if _, err := e.core.SQLDB().ExecContext(ctx, q, pg.ID, pg.Name, desc, now); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	pg.Description = desc
	pg.CreatedAt = unixMilliToRFC3339(now)
	return &pg, nil
}

type createPGBulkInput struct{ Body BulkItems[PermissionGroupDTO] `json:"body"` }

func (e *PermissionGroupsResource) CreateMany(ctx context.Context, in *createPGBulkInput) (*[]PermissionGroupDTO, error) {
	out := make([]PermissionGroupDTO, 0, len(in.Body.Items))
	for _, item := range in.Body.Items {
		created, err := e.Create(ctx, &createPGInput{Body: item})
		if err != nil {
			return nil, err
		}
		out = append(out, *created)
	}
	return &out, nil
}

type updatePGInput struct {
	ID   string `path:"id"`
	Body PermissionGroupDTO `json:"body"`
}

func (e *PermissionGroupsResource) Update(ctx context.Context, in *updatePGInput) (*PermissionGroupDTO, error) {
	if e.core == nil {
		return nil, httpx.NewError(500, "db_missing")
	}
	if err := enforce(ctx, e.engine, "permission-groups:write", "/permission-groups"); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(in.ID)
	name := strings.TrimSpace(in.Body.Name)
	desc := strings.TrimSpace(in.Body.Description)
	if id == "" || name == "" {
		return nil, httpx.NewError(422, "validation")
	}
	q := fmt.Sprintf("UPDATE iam_permission_groups SET name=%s, description=%s WHERE id=%s", bind(e.core, 1), bind(e.core, 2), bind(e.core, 3))
	if _, err := e.core.SQLDB().ExecContext(ctx, q, name, desc, id); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	return e.Get(ctx, &userIDPath{ID: id})
}

func (e *PermissionGroupsResource) UpdateByID(ctx context.Context, in *updatePGInput) (*PermissionGroupDTO, error) {
	return e.Update(ctx, in)
}

type updatePGBulkInput struct {
	ID   string `query:"id"`
	Body PermissionGroupDTO `json:"body"`
}

func (e *PermissionGroupsResource) UpdateMany(ctx context.Context, in *updatePGBulkInput) (*[]PermissionGroupDTO, error) {
	ids := splitIDs(in.ID)
	out := make([]PermissionGroupDTO, 0, len(ids))
	for _, id := range ids {
		item, err := e.Update(ctx, &updatePGInput{ID: id, Body: in.Body})
		if err != nil {
			return nil, err
		}
		out = append(out, *item)
	}
	return &out, nil
}

func (e *PermissionGroupsResource) Delete(ctx context.Context, in *userIDPath) (*struct{}, error) {
	if e.core == nil {
		return nil, httpx.NewError(500, "db_missing")
	}
	if err := enforce(ctx, e.engine, "permission-groups:write", "/permission-groups"); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(in.ID)
	if _, err := e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_role_permission_groups WHERE group_id=%s", bind(e.core, 1)), id); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	if _, err := e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_permission_group_permissions WHERE group_id=%s", bind(e.core, 1)), id); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	if _, err := e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_permission_groups WHERE id=%s", bind(e.core, 1)), id); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	return &struct{}{}, nil
}

func (e *PermissionGroupsResource) DeleteByID(ctx context.Context, in *userIDPath) (*struct{}, error) {
	return e.Delete(ctx, in)
}

func (e *PermissionGroupsResource) DeleteMany(ctx context.Context, in *idsQuery) (*[]PermissionGroupDTO, error) {
	if err := enforce(ctx, e.engine, "permission-groups:write", "/permission-groups"); err != nil {
		return nil, err
	}
	ids := splitIDs(in.ID)
	out := make([]PermissionGroupDTO, 0, len(ids))
	for _, id := range ids {
		item, err := e.Get(ctx, &userIDPath{ID: id})
		if err == nil && item != nil {
			out = append(out, *item)
		}
		if _, err := e.Delete(ctx, &userIDPath{ID: id}); err != nil {
			return nil, err
		}
	}
	return &out, nil
}

