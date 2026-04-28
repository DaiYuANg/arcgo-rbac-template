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

type PermissionsResource struct {
	engine *authx.Engine
	core   *dbx.DB
}

func (e *PermissionsResource) FiberBinding() FiberBinding {
	return FiberBinding{
		Prefix:  "/api/permissions",
		Handler: requirePermissionFiber(e.engine, "permissions:read", "/permissions"),
	}
}

func (e *PermissionsResource) EndpointSpec() httpx.EndpointSpec {
	return httpx.EndpointSpec{
		Prefix:        "/api/permissions",
		Tags:          httpx.Tags("permissions"),
		SummaryPrefix: "Permissions",
		Description:   "Permissions resource",
	}
}

type permListInput struct {
	ID       string `query:"id"`
	Page     int64  `query:"page"`
	PageSize int64  `query:"pageSize"`
	Q        string `query:"q"`
	Sort     string `query:"sort"`
	Order    string `query:"order"`
	NameLike string `query:"name_like"`
	CodeLike string `query:"code_like"`
}

func (e *PermissionsResource) Register(registrar httpx.Registrar) {
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

func (e *PermissionsResource) ListOrGetMany(ctx context.Context, in *permListInput) (*PageResponse[PermissionDTO], error) {
	if strings.TrimSpace(in.ID) != "" {
		items := []PermissionDTO{}
		for _, id := range splitIDs(in.ID) {
			item, err := e.Get(ctx, &userIDPath{ID: id})
			if err == nil && item != nil {
				items = append(items, *item)
			}
		}
		pageSize := int64(len(items))
		return &PageResponse[PermissionDTO]{Items: items, Total: pageSize, Page: 1, PageSize: pageSize}, nil
	}
	return e.List(ctx, in)
}

func (e *PermissionsResource) List(ctx context.Context, in *permListInput) (*PageResponse[PermissionDTO], error) {
	if e.core == nil {
		return nil, httpx.NewError(500, "db_missing")
	}
	if in.Page <= 0 || in.PageSize <= 0 {
		return nil, httpx.NewError(400, "validation", fmt.Errorf("page and pageSize are required"))
	}
	where := " WHERE 1=1"
	args := []any{}
	addLike := func(field, value string) {
		v := strings.TrimSpace(value)
		if v == "" {
			return
		}
		args = append(args, "%"+v+"%")
		where += fmt.Sprintf(" AND %s LIKE %s", field, bind(e.core, len(args)))
	}
	addLike("name", in.NameLike)
	addLike("code", in.CodeLike)
	addLike("name", in.Q)
	addLike("code", in.Q)
	orderSQL, err := orderBy(in.Sort, in.Order, map[string]string{
		"id":        "id",
		"name":      "name",
		"code":      "code",
		"createdAt": "created_at",
	})
	if err != nil {
		return nil, httpx.NewError(400, "validation", err)
	}
	var total int64
	if err := e.core.SQLDB().QueryRowContext(ctx, "SELECT COUNT(1) FROM iam_permissions"+where, args...).Scan(&total); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	offset := (in.Page - 1) * in.PageSize
	args2 := append([]any{}, args...)
	args2 = append(args2, in.PageSize, offset)
	limitBind := bind(e.core, len(args2)-1)
	offsetBind := bind(e.core, len(args2))

	// groupId is represented by join-table lookup (0..1 in practice).
	sqlText := "SELECT p.id, p.name, p.code, p.created_at, g.group_id FROM iam_permissions p " +
		"LEFT JOIN iam_permission_group_permissions g ON g.perm_id = p.id" +
		where + orderSQL + " LIMIT " + limitBind + " OFFSET " + offsetBind
	rows, err := e.core.SQLDB().QueryContext(ctx, sqlText, args2...)
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	defer rows.Close()
	items := make([]PermissionDTO, 0, in.PageSize)
	for rows.Next() {
		var id, name, code string
		var createdAt int64
		var groupID *string
		if err := rows.Scan(&id, &name, &code, &createdAt, &groupID); err != nil {
			return nil, httpx.NewError(500, "unknown", err)
		}
		items = append(items, PermissionDTO{ID: id, Name: name, Code: code, GroupID: groupID, CreatedAt: unixMilliToRFC3339(createdAt)})
	}
	return &PageResponse[PermissionDTO]{Items: items, Total: total, Page: in.Page, PageSize: in.PageSize}, nil
}

func (e *PermissionsResource) Get(ctx context.Context, in *userIDPath) (*PermissionDTO, error) {
	if e.core == nil {
		return nil, httpx.NewError(500, "db_missing")
	}
	id := strings.TrimSpace(in.ID)
	q := fmt.Sprintf("SELECT p.id, p.name, p.code, p.created_at, g.group_id FROM iam_permissions p LEFT JOIN iam_permission_group_permissions g ON g.perm_id=p.id WHERE p.id=%s", bind(e.core, 1))
	row := e.core.SQLDB().QueryRowContext(ctx, q, id)
	var name, code string
	var createdAt int64
	var groupID *string
	if err := row.Scan(&id, &name, &code, &createdAt, &groupID); err != nil {
		return nil, httpx.NewError(404, "not_found", err)
	}
	return &PermissionDTO{ID: id, Name: name, Code: code, GroupID: groupID, CreatedAt: unixMilliToRFC3339(createdAt)}, nil
}

type createPermInput struct{ Body PermissionDTO `json:"body"` }

func (e *PermissionsResource) Create(ctx context.Context, in *createPermInput) (*PermissionDTO, error) {
	if e.core == nil {
		return nil, httpx.NewError(500, "db_missing")
	}
	if err := enforce(ctx, e.engine, "permissions:write", "/permissions"); err != nil {
		return nil, err
	}
	p := in.Body
	p.ID = strings.TrimSpace(p.ID)
	p.Name = strings.TrimSpace(p.Name)
	p.Code = strings.TrimSpace(p.Code)
	if p.ID == "" || p.Name == "" || p.Code == "" {
		return nil, httpx.NewError(422, "validation")
	}
	now := nowUnixMilli()
	q := fmt.Sprintf("INSERT INTO iam_permissions (id, name, code, created_at) VALUES (%s,%s,%s,%s)", bind(e.core, 1), bind(e.core, 2), bind(e.core, 3), bind(e.core, 4))
	if _, err := e.core.SQLDB().ExecContext(ctx, q, p.ID, p.Name, p.Code, now); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	if err := e.setPermissionGroup(ctx, p.ID, p.GroupID); err != nil {
		return nil, err
	}
	p.CreatedAt = unixMilliToRFC3339(now)
	return &p, nil
}

type createPermBulkInput struct{ Body BulkItems[PermissionDTO] `json:"body"` }

func (e *PermissionsResource) CreateMany(ctx context.Context, in *createPermBulkInput) (*[]PermissionDTO, error) {
	out := make([]PermissionDTO, 0, len(in.Body.Items))
	for _, item := range in.Body.Items {
		created, err := e.Create(ctx, &createPermInput{Body: item})
		if err != nil {
			return nil, err
		}
		out = append(out, *created)
	}
	return &out, nil
}

type updatePermInput struct {
	ID   string `path:"id"`
	Body PermissionDTO `json:"body"`
}

func (e *PermissionsResource) Update(ctx context.Context, in *updatePermInput) (*PermissionDTO, error) {
	if e.core == nil {
		return nil, httpx.NewError(500, "db_missing")
	}
	if err := enforce(ctx, e.engine, "permissions:write", "/permissions"); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(in.ID)
	name := strings.TrimSpace(in.Body.Name)
	code := strings.TrimSpace(in.Body.Code)
	if id == "" || name == "" || code == "" {
		return nil, httpx.NewError(422, "validation")
	}
	q := fmt.Sprintf("UPDATE iam_permissions SET name=%s, code=%s WHERE id=%s", bind(e.core, 1), bind(e.core, 2), bind(e.core, 3))
	if _, err := e.core.SQLDB().ExecContext(ctx, q, name, code, id); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	if err := e.setPermissionGroup(ctx, id, in.Body.GroupID); err != nil {
		return nil, err
	}
	return e.Get(ctx, &userIDPath{ID: id})
}

type updatePermBulkInput struct {
	ID   string `query:"id"`
	Body struct {
		GroupID *string `json:"groupId"`
	} `json:"body"`
}

func (e *PermissionsResource) UpdateMany(ctx context.Context, in *updatePermBulkInput) (*[]PermissionDTO, error) {
	if e.core == nil {
		return nil, httpx.NewError(500, "db_missing")
	}
	if err := enforce(ctx, e.engine, "permissions:write", "/permissions"); err != nil {
		return nil, err
	}
	ids := splitIDs(in.ID)
	out := make([]PermissionDTO, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if err := e.setPermissionGroup(ctx, id, in.Body.GroupID); err != nil {
			return nil, err
		}
		item, err := e.Get(ctx, &userIDPath{ID: id})
		if err == nil && item != nil {
			out = append(out, *item)
		}
	}
	return &out, nil
}

func (e *PermissionsResource) Delete(ctx context.Context, in *userIDPath) (*struct{}, error) {
	if e.core == nil {
		return nil, httpx.NewError(500, "db_missing")
	}
	if err := enforce(ctx, e.engine, "permissions:write", "/permissions"); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(in.ID)
	_, _ = e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_permission_group_permissions WHERE perm_id=%s", bind(e.core, 1)), id)
	if _, err := e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_permissions WHERE id=%s", bind(e.core, 1)), id); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	return &struct{}{}, nil
}

func (e *PermissionsResource) DeleteMany(ctx context.Context, in *idsQuery) (*[]PermissionDTO, error) {
	if err := enforce(ctx, e.engine, "permissions:write", "/permissions"); err != nil {
		return nil, err
	}
	ids := splitIDs(in.ID)
	out := make([]PermissionDTO, 0, len(ids))
	for _, id := range ids {
		item, err := e.Get(ctx, &userIDPath{ID: id})
		if err == nil && item != nil {
			out = append(out, *item)
		}
		_, _ = e.Delete(ctx, &userIDPath{ID: id})
	}
	return &out, nil
}

func (e *PermissionsResource) setPermissionGroup(ctx context.Context, permID string, groupID *string) error {
	// enforce 0..1 mapping by clearing existing assignments
	if _, err := e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_permission_group_permissions WHERE perm_id=%s", bind(e.core, 1)), permID); err != nil {
		return httpx.NewError(500, "unknown", err)
	}
	if groupID == nil || strings.TrimSpace(*groupID) == "" {
		return nil
	}
	gid := strings.TrimSpace(*groupID)
	q := fmt.Sprintf("INSERT INTO iam_permission_group_permissions (group_id, perm_id) VALUES (%s,%s)", bind(e.core, 1), bind(e.core, 2))
	if _, err := e.core.SQLDB().ExecContext(ctx, q, gid, permID); err != nil {
		return httpx.NewError(500, "unknown", err)
	}
	return nil
}

