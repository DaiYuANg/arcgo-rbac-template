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

type RolesResource struct {
	engine *authx.Engine
	core   *dbx.DB
}

func (e *RolesResource) FiberBinding() FiberBinding {
	return FiberBinding{
		Prefix:  "/api/roles",
		Handler: requirePermissionFiber(e.engine, "roles:read", "/roles"),
	}
}

func (e *RolesResource) EndpointSpec() httpx.EndpointSpec {
	return httpx.EndpointSpec{
		Prefix:        "/api/roles",
		Tags:          httpx.Tags("roles"),
		SummaryPrefix: "Roles",
		Description:   "Roles resource",
	}
}

type rolesListInput struct {
	ID       string `query:"id"`
	Page     int64  `query:"page"`
	PageSize int64  `query:"pageSize"`
	Q        string `query:"q"`
	Sort     string `query:"sort"`
	Order    string `query:"order"`
	NameLike string `query:"name_like"`
}

func (e *RolesResource) Register(registrar httpx.Registrar) {
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

func (e *RolesResource) ListOrGetMany(ctx context.Context, in *rolesListInput) (*PageResponse[RoleDTO], error) {
	if strings.TrimSpace(in.ID) != "" {
		items, _ := e.getMany(ctx, splitIDs(in.ID))
		pageSize := int64(len(items))
		return &PageResponse[RoleDTO]{Items: items, Total: pageSize, Page: 1, PageSize: pageSize}, nil
	}
	return e.List(ctx, in)
}

func (e *RolesResource) List(ctx context.Context, in *rolesListInput) (*PageResponse[RoleDTO], error) {
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
	countSQL := "SELECT COUNT(1) FROM iam_roles" + where
	var total int64
	if err := e.core.SQLDB().QueryRowContext(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	offset := (in.Page - 1) * in.PageSize
	args2 := append([]any{}, args...)
	args2 = append(args2, in.PageSize, offset)
	limitBind := bind(e.core, len(args2)-1)
	offsetBind := bind(e.core, len(args2))
	listSQL := "SELECT id, name, description, created_at FROM iam_roles" + where + orderSQL +
		" LIMIT " + limitBind + " OFFSET " + offsetBind
	rows, err := e.core.SQLDB().QueryContext(ctx, listSQL, args2...)
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	defer rows.Close()
	items := make([]RoleDTO, 0, in.PageSize)
	for rows.Next() {
		var id, name, desc string
		var createdAt int64
		if err := rows.Scan(&id, &name, &desc, &createdAt); err != nil {
			return nil, httpx.NewError(500, "unknown", err)
		}
		gids, _ := e.listRoleGroupIDs(ctx, id)
		items = append(items, RoleDTO{ID: id, Name: name, Description: desc, PermissionGroupIDs: gids, CreatedAt: unixMilliToRFC3339(createdAt)})
	}
	return &PageResponse[RoleDTO]{Items: items, Total: total, Page: in.Page, PageSize: in.PageSize}, nil
}

func (e *RolesResource) Get(ctx context.Context, in *userIDPath) (*RoleDTO, error) {
	if e.core == nil {
		return nil, httpx.NewError(500, "db_missing")
	}
	id := strings.TrimSpace(in.ID)
	if id == "" {
		return nil, httpx.NewError(422, "validation")
	}
	q := fmt.Sprintf("SELECT id, name, description, created_at FROM iam_roles WHERE id=%s", bind(e.core, 1))
	row := e.core.SQLDB().QueryRowContext(ctx, q, id)
	var name, desc string
	var createdAt int64
	if err := row.Scan(&id, &name, &desc, &createdAt); err != nil {
		return nil, httpx.NewError(404, "not_found", err)
	}
	gids, _ := e.listRoleGroupIDs(ctx, id)
	return &RoleDTO{ID: id, Name: name, Description: desc, PermissionGroupIDs: gids, CreatedAt: unixMilliToRFC3339(createdAt)}, nil
}

type createRoleInput struct {
	Body RoleDTO `json:"body"`
}

func (e *RolesResource) Create(ctx context.Context, in *createRoleInput) (*RoleDTO, error) {
	if e.core == nil {
		return nil, httpx.NewError(500, "db_missing")
	}
	if err := enforce(ctx, e.engine, "roles:write", "/roles"); err != nil {
		return nil, err
	}
	r := in.Body
	r.ID = strings.TrimSpace(r.ID)
	r.Name = strings.TrimSpace(r.Name)
	if r.ID == "" || r.Name == "" {
		return nil, httpx.NewError(422, "validation")
	}
	desc := strings.TrimSpace(r.Description)
	now := nowUnixMilli()
	q := fmt.Sprintf("INSERT INTO iam_roles (id, name, description, created_at) VALUES (%s,%s,%s,%s)", bind(e.core, 1), bind(e.core, 2), bind(e.core, 3), bind(e.core, 4))
	if _, err := e.core.SQLDB().ExecContext(ctx, q, r.ID, r.Name, desc, now); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	if err := e.replaceRoleGroups(ctx, r.ID, r.PermissionGroupIDs); err != nil {
		return nil, err
	}
	r.CreatedAt = unixMilliToRFC3339(now)
	r.Description = desc
	return &r, nil
}

type createRolesBulkInput struct {
	Body BulkItems[RoleDTO] `json:"body"`
}

func (e *RolesResource) CreateMany(ctx context.Context, in *createRolesBulkInput) (*[]RoleDTO, error) {
	out := make([]RoleDTO, 0, len(in.Body.Items))
	for _, item := range in.Body.Items {
		created, err := e.Create(ctx, &createRoleInput{Body: item})
		if err != nil {
			return nil, err
		}
		out = append(out, *created)
	}
	return &out, nil
}

type updateRoleInput struct {
	ID   string `path:"id"`
	Body RoleDTO `json:"body"`
}

func (e *RolesResource) Update(ctx context.Context, in *updateRoleInput) (*RoleDTO, error) {
	if e.core == nil {
		return nil, httpx.NewError(500, "db_missing")
	}
	if err := enforce(ctx, e.engine, "roles:write", "/roles"); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(in.ID)
	name := strings.TrimSpace(in.Body.Name)
	desc := strings.TrimSpace(in.Body.Description)
	if id == "" || name == "" {
		return nil, httpx.NewError(422, "validation")
	}
	q := fmt.Sprintf("UPDATE iam_roles SET name=%s, description=%s WHERE id=%s", bind(e.core, 1), bind(e.core, 2), bind(e.core, 3))
	if _, err := e.core.SQLDB().ExecContext(ctx, q, name, desc, id); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	if err := e.replaceRoleGroups(ctx, id, in.Body.PermissionGroupIDs); err != nil {
		return nil, err
	}
	return e.Get(ctx, &userIDPath{ID: id})
}

type updateRolesBulkInput struct {
	ID   string  `query:"id"`
	Body RoleDTO `json:"body"`
}

func (e *RolesResource) UpdateMany(ctx context.Context, in *updateRolesBulkInput) (*[]RoleDTO, error) {
	ids := splitIDs(in.ID)
	out := make([]RoleDTO, 0, len(ids))
	for _, id := range ids {
		dto, err := e.Update(ctx, &updateRoleInput{ID: id, Body: in.Body})
		if err != nil {
			return nil, err
		}
		out = append(out, *dto)
	}
	return &out, nil
}

func (e *RolesResource) Delete(ctx context.Context, in *userIDPath) (*struct{}, error) {
	if e.core == nil {
		return nil, httpx.NewError(500, "db_missing")
	}
	if err := enforce(ctx, e.engine, "roles:write", "/roles"); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(in.ID)
	if id == "" {
		return nil, httpx.NewError(422, "validation")
	}
	_, _ = e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_user_roles WHERE role_id=%s", bind(e.core, 1)), id)
	_, _ = e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_role_permission_groups WHERE role_id=%s", bind(e.core, 1)), id)
	if _, err := e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_roles WHERE id=%s", bind(e.core, 1)), id); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	return &struct{}{}, nil
}

func (e *RolesResource) DeleteMany(ctx context.Context, in *idsQuery) (*[]RoleDTO, error) {
	if err := enforce(ctx, e.engine, "roles:write", "/roles"); err != nil {
		return nil, err
	}
	ids := splitIDs(in.ID)
	out := make([]RoleDTO, 0, len(ids))
	for _, id := range ids {
		item, err := e.Get(ctx, &userIDPath{ID: id})
		if err == nil && item != nil {
			out = append(out, *item)
		}
		_, _ = e.Delete(ctx, &userIDPath{ID: id})
	}
	return &out, nil
}

func (e *RolesResource) listRoleGroupIDs(ctx context.Context, roleID string) ([]string, error) {
	rows, err := e.core.SQLDB().QueryContext(ctx, fmt.Sprintf("SELECT group_id FROM iam_role_permission_groups WHERE role_id=%s", bind(e.core, 1)), roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var gid string
		if err := rows.Scan(&gid); err != nil {
			return nil, err
		}
		out = append(out, gid)
	}
	return out, rows.Err()
}

func (e *RolesResource) replaceRoleGroups(ctx context.Context, roleID string, groupIDs []string) error {
	if groupIDs == nil {
		return nil
	}
	if _, err := e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_role_permission_groups WHERE role_id=%s", bind(e.core, 1)), roleID); err != nil {
		return httpx.NewError(500, "unknown", err)
	}
	for _, gid := range groupIDs {
		gid = strings.TrimSpace(gid)
		if gid == "" {
			continue
		}
		q := fmt.Sprintf("INSERT INTO iam_role_permission_groups (role_id, group_id) VALUES (%s,%s)", bind(e.core, 1), bind(e.core, 2))
		if _, err := e.core.SQLDB().ExecContext(ctx, q, roleID, gid); err != nil {
			return httpx.NewError(500, "unknown", err)
		}
	}
	return nil
}

func (e *RolesResource) getMany(ctx context.Context, ids []string) ([]RoleDTO, error) {
	out := []RoleDTO{}
	for _, id := range ids {
		item, err := e.Get(ctx, &userIDPath{ID: id})
		if err == nil && item != nil {
			out = append(out, *item)
		}
	}
	return out, nil
}

