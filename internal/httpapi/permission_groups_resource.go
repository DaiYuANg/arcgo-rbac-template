package httpapi

import (
	"context"
	"fmt"
	"strings"

	"github.com/arcgolabs/authx"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/httpx"
	"github.com/danielgtaylor/huma/v2"
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
	httpx.MustGroupGet(g, "", e.ListOrGetMany, func(op *huma.Operation) { op.Summary = "List / Get many" })
	httpx.MustGroupGet(g, "/{id}", e.Get, func(op *huma.Operation) { op.Summary = "Detail" })
	httpx.MustGroupPost(g, "", e.Create, func(op *huma.Operation) { op.Summary = "Create" })
	httpx.MustGroupPost(g, "/bulk", e.CreateMany, func(op *huma.Operation) { op.Summary = "Create many" })
	httpx.MustGroupPatch(g, "/{id}", e.Update, func(op *huma.Operation) { op.Summary = "Update" })
	httpx.MustGroupPatch(g, "/bulk", e.UpdateMany, func(op *huma.Operation) { op.Summary = "Update many" })
	httpx.MustGroupDelete(g, "/{id}", e.Delete, func(op *huma.Operation) { op.Summary = "Delete" })
	httpx.MustGroupDelete(g, "", e.DeleteMany, func(op *huma.Operation) { op.Summary = "Delete many" })
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
	where := " WHERE 1=1"
	args := []any{}
	if v := strings.TrimSpace(in.NameLike); v != "" {
		args = append(args, "%"+v+"%")
		where += fmt.Sprintf(" AND name LIKE %s", bind(e.core, len(args)))
	}
	if v := strings.TrimSpace(in.Q); v != "" {
		args = append(args, "%"+v+"%")
		where += fmt.Sprintf(" AND (name LIKE %s OR description LIKE %s)", bind(e.core, len(args)), bind(e.core, len(args)))
	}
	orderSQL, err := orderBy(in.Sort, in.Order, map[string]string{
		"id":        "id",
		"name":      "name",
		"createdAt": "created_at",
	})
	if err != nil {
		return nil, httpx.NewError(400, "validation", err)
	}
	var total int64
	if err := e.core.SQLDB().QueryRowContext(ctx, "SELECT COUNT(1) FROM iam_permission_groups"+where, args...).Scan(&total); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	offset := (in.Page - 1) * in.PageSize
	args2 := append([]any{}, args...)
	args2 = append(args2, in.PageSize, offset)
	limitBind := bind(e.core, len(args2)-1)
	offsetBind := bind(e.core, len(args2))
	rows, err := e.core.SQLDB().QueryContext(ctx, "SELECT id, name, description, created_at FROM iam_permission_groups"+where+orderSQL+" LIMIT "+limitBind+" OFFSET "+offsetBind, args2...)
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	defer rows.Close()
	items := make([]PermissionGroupDTO, 0, in.PageSize)
	for rows.Next() {
		var id, name, desc string
		var createdAt int64
		if err := rows.Scan(&id, &name, &desc, &createdAt); err != nil {
			return nil, httpx.NewError(500, "unknown", err)
		}
		items = append(items, PermissionGroupDTO{ID: id, Name: name, Description: desc, CreatedAt: unixMilliToRFC3339(createdAt)})
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
	_, _ = e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_role_permission_groups WHERE group_id=%s", bind(e.core, 1)), id)
	_, _ = e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_permission_group_permissions WHERE group_id=%s", bind(e.core, 1)), id)
	if _, err := e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_permission_groups WHERE id=%s", bind(e.core, 1)), id); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	return &struct{}{}, nil
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
		_, _ = e.Delete(ctx, &userIDPath{ID: id})
	}
	return &out, nil
}

