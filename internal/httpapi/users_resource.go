package httpapi

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/arcgolabs/authx"
	"github.com/DaiYuANg/arcgo/kvx"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/httpx"
	"github.com/danielgtaylor/huma/v2"
)

type UsersResource struct {
	engine *authx.Engine
	core   *dbx.DB
	cache  kvx.KV
	cachePrefix string
	cacheTTL    time.Duration
}

func (e *UsersResource) FiberBinding() FiberBinding {
	return FiberBinding{
		Prefix:  "/api/users",
		Handler: requirePermissionFiber(e.engine, "users:read", "/users"),
	}
}

func (e *UsersResource) EndpointSpec() httpx.EndpointSpec {
	return httpx.EndpointSpec{
		Prefix:        "/api/users",
		Tags:          httpx.Tags("users"),
		SummaryPrefix: "Users",
		Description:   "Users resource",
	}
}

type usersListInput struct {
	Page     int64  `query:"page" minimum:"1"`
	PageSize int64  `query:"pageSize" minimum:"1"`
	Q        string `query:"q"`
	Sort     string `query:"sort"`
	Order    string `query:"order"`
	NameLike string `query:"name_like"`
	EmailLike string `query:"email_like"`
}

func (e *UsersResource) Register(registrar httpx.Registrar) {
	g := registrar.Scope()
	httpx.MustGroupGet(g, "", e.ListOrGetMany, func(op *huma.Operation) { op.Summary = "List / Get many" })
	httpx.MustGroupGet(g, "/{id}", e.Get, func(op *huma.Operation) { op.Summary = "Detail" })
	httpx.MustGroupPost(g, "", e.Create, func(op *huma.Operation) { op.Summary = "Create" })
	httpx.MustGroupPost(g, "/bulk", e.CreateMany, func(op *huma.Operation) { op.Summary = "Create many" })
	httpx.MustGroupPatch(g, "/{id}", e.Update, func(op *huma.Operation) { op.Summary = "Update" })
	httpx.MustGroupPatch(g, "/bulk", e.UpdateMany, func(op *huma.Operation) { op.Summary = "Update many" })
	httpx.MustGroupDelete(g, "/{id}", e.Delete, func(op *huma.Operation) { op.Summary = "Delete" })
	httpx.MustGroupDelete(g, "", e.DeleteManyOrGetMany, func(op *huma.Operation) { op.Summary = "Delete many / Get many" })
}

func (e *UsersResource) List(ctx context.Context, in *usersListInput) (*PageResponse[UserDTO], error) {
	if e.core == nil {
		return nil, httpx.NewError(500, "db_missing")
	}
	if in.Page <= 0 || in.PageSize <= 0 {
		return nil, httpx.NewError(400, "validation", fmt.Errorf("page and pageSize are required"))
	}

	where := " WHERE 1=1"
	args := []any{}
	addLike := func(field string, value string) {
		v := strings.TrimSpace(value)
		if v == "" {
			return
		}
		args = append(args, "%"+v+"%")
		where += fmt.Sprintf(" AND %s LIKE %s", field, bind(e.core, len(args)))
	}
	addLike("name", in.NameLike)
	addLike("email", in.EmailLike)
	addLike("name", in.Q)
	addLike("email", in.Q)

	orderSQL, err := orderBy(in.Sort, in.Order, map[string]string{
		"id":        "id",
		"email":     "email",
		"name":      "name",
		"createdAt": "created_at",
	})
	if err != nil {
		return nil, httpx.NewError(400, "validation", err)
	}

	countSQL := "SELECT COUNT(1) FROM iam_users" + where
	var total int64
	if err := e.core.SQLDB().QueryRowContext(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}

	offset := (in.Page - 1) * in.PageSize
	args2 := append([]any{}, args...)
	args2 = append(args2, in.PageSize, offset)
	limitBind := bind(e.core, len(args2)-1)
	offsetBind := bind(e.core, len(args2))

	listSQL := "SELECT id, email, name, created_at FROM iam_users" + where + orderSQL +
		" LIMIT " + limitBind + " OFFSET " + offsetBind
	rows, err := e.core.SQLDB().QueryContext(ctx, listSQL, args2...)
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	defer rows.Close()

	items := make([]UserDTO, 0, in.PageSize)
	for rows.Next() {
		var id, email, name string
		var createdAt int64
		if err := rows.Scan(&id, &email, &name, &createdAt); err != nil {
			return nil, httpx.NewError(500, "unknown", err)
		}
		items = append(items, UserDTO{
			ID:        id,
			Email:     email,
			Name:      name,
			CreatedAt: unixMilliToRFC3339(createdAt),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}

	return &PageResponse[UserDTO]{
		Items:    items,
		Total:    total,
		Page:     in.Page,
		PageSize: in.PageSize,
	}, nil
}

type userIDPath struct {
	ID string `path:"id"`
}

func (e *UsersResource) Get(ctx context.Context, in *userIDPath) (*UserDTO, error) {
	if e.core == nil {
		return nil, httpx.NewError(500, "db_missing")
	}
	id := strings.TrimSpace(in.ID)
	if id == "" {
		return nil, httpx.NewError(400, "validation")
	}
	b1 := bind(e.core, 1)
	row := e.core.SQLDB().QueryRowContext(ctx, fmt.Sprintf("SELECT id, email, name, created_at FROM iam_users WHERE id = %s", b1), id)
	var email, name string
	var createdAt int64
	if err := row.Scan(&id, &email, &name, &createdAt); err != nil {
		return nil, httpx.NewError(404, "not_found", err)
	}
	roleIDs, _ := e.listUserRoleIDs(ctx, id)
	return &UserDTO{ID: id, Email: email, Name: name, RoleIDs: roleIDs, CreatedAt: unixMilliToRFC3339(createdAt)}, nil
}

type createUserInput struct {
	Body UserDTO `json:"body"`
}

func (e *UsersResource) Create(ctx context.Context, in *createUserInput) (*UserDTO, error) {
	if e.core == nil {
		return nil, httpx.NewError(500, "db_missing")
	}
	if err := enforce(ctx, e.engine, "users:write", "/users"); err != nil {
		return nil, err
	}
	u := in.Body
	u.ID = strings.TrimSpace(u.ID)
	u.Email = strings.TrimSpace(u.Email)
	u.Name = strings.TrimSpace(u.Name)
	if u.ID == "" || u.Email == "" || u.Name == "" {
		return nil, httpx.NewError(422, "validation")
	}
	now := nowUnixMilli()
	q := fmt.Sprintf(
		"INSERT INTO iam_users (id, email, name, created_at) VALUES (%s,%s,%s,%s)",
		bind(e.core, 1), bind(e.core, 2), bind(e.core, 3), bind(e.core, 4),
	)
	if _, err := e.core.SQLDB().ExecContext(ctx, q, u.ID, u.Email, u.Name, now); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	if err := e.replaceUserRoles(ctx, u.ID, u.RoleIDs); err != nil {
		return nil, err
	}
	u.CreatedAt = unixMilliToRFC3339(now)
	return &u, nil
}

type createUsersBulkInput struct {
	Body BulkItems[UserDTO] `json:"body"`
}

func (e *UsersResource) CreateMany(ctx context.Context, in *createUsersBulkInput) (*[]UserDTO, error) {
	out := make([]UserDTO, 0, len(in.Body.Items))
	for _, item := range in.Body.Items {
		created, err := e.Create(ctx, &createUserInput{Body: item})
		if err != nil {
			return nil, err
		}
		out = append(out, *created)
	}
	return &out, nil
}

type updateUserInput struct {
	ID   string  `path:"id"`
	Body UserDTO `json:"body"`
}

func (e *UsersResource) Update(ctx context.Context, in *updateUserInput) (*UserDTO, error) {
	if e.core == nil {
		return nil, httpx.NewError(500, "db_missing")
	}
	if err := enforce(ctx, e.engine, "users:write", "/users"); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(in.ID)
	if id == "" {
		return nil, httpx.NewError(422, "validation")
	}
	email := strings.TrimSpace(in.Body.Email)
	name := strings.TrimSpace(in.Body.Name)
	if email == "" || name == "" {
		return nil, httpx.NewError(422, "validation")
	}
	q := fmt.Sprintf("UPDATE iam_users SET email=%s, name=%s WHERE id=%s", bind(e.core, 1), bind(e.core, 2), bind(e.core, 3))
	if _, err := e.core.SQLDB().ExecContext(ctx, q, email, name, id); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	if err := e.replaceUserRoles(ctx, id, in.Body.RoleIDs); err != nil {
		return nil, err
	}
	dto, err := e.Get(ctx, &userIDPath{ID: id})
	if err != nil {
		return nil, err
	}
	return dto, nil
}

type updateUsersBulkInput struct {
	ID   string  `query:"id"`
	Body UserDTO `json:"body"`
}

func (e *UsersResource) UpdateMany(ctx context.Context, in *updateUsersBulkInput) (*[]UserDTO, error) {
	ids := splitIDs(in.ID)
	out := make([]UserDTO, 0, len(ids))
	for _, id := range ids {
		dto, err := e.Update(ctx, &updateUserInput{ID: id, Body: in.Body})
		if err != nil {
			return nil, err
		}
		out = append(out, *dto)
	}
	return &out, nil
}

func (e *UsersResource) Delete(ctx context.Context, in *userIDPath) (*struct{}, error) {
	if e.core == nil {
		return nil, httpx.NewError(500, "db_missing")
	}
	if err := enforce(ctx, e.engine, "users:write", "/users"); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(in.ID)
	if id == "" {
		return nil, httpx.NewError(422, "validation")
	}
	_, _ = e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_user_roles WHERE user_id=%s", bind(e.core, 1)), id)
	if _, err := e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_users WHERE id=%s", bind(e.core, 1)), id); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	return &struct{}{}, nil
}

type idsQuery struct {
	ID string `query:"id"`
}

type usersListOrManyInput struct {
	idsQuery
	usersListInput
}

func (e *UsersResource) ListOrGetMany(ctx context.Context, in *usersListOrManyInput) (*PageResponse[UserDTO], error) {
	if strings.TrimSpace(in.ID) != "" {
		items, err := e.GetMany(ctx, &idsQuery{ID: in.ID})
		if err != nil {
			return nil, err
		}
		pageSize := int64(0)
		if items != nil {
			pageSize = int64(len(*items))
		}
		return &PageResponse[UserDTO]{
			Items:    loOrEmpty(items),
			Total:    pageSize,
			Page:     1,
			PageSize: pageSize,
		}, nil
	}
	return e.List(ctx, &in.usersListInput)
}

func loOrEmpty(items *[]UserDTO) []UserDTO {
	if items == nil {
		return []UserDTO{}
	}
	return *items
}

func (e *UsersResource) DeleteManyOrGetMany(ctx context.Context, in *idsQuery) (*[]UserDTO, error) {
	if err := enforce(ctx, e.engine, "users:write", "/users"); err != nil {
		return nil, err
	}
	// This handler is only used for DELETE many (method-bound), but httpx's typed inputs are shared.
	// We still keep it returning []UserDTO to match contract when needed.
	ids := splitIDs(in.ID)
	out := make([]UserDTO, 0, len(ids))
	for _, id := range ids {
		item, err := e.Get(ctx, &userIDPath{ID: id})
		if err == nil && item != nil {
			out = append(out, *item)
		}
		_, _ = e.Delete(ctx, &userIDPath{ID: id})
	}
	return &out, nil
}

func (e *UsersResource) GetMany(ctx context.Context, in *idsQuery) (*[]UserDTO, error) {
	ids := splitIDs(in.ID)
	out := make([]UserDTO, 0, len(ids))
	for _, id := range ids {
		item, err := e.Get(ctx, &userIDPath{ID: id})
		if err != nil {
			continue
		}
		out = append(out, *item)
	}
	return &out, nil
}

func splitIDs(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (e *UsersResource) listUserRoleIDs(ctx context.Context, userID string) ([]string, error) {
	rows, err := e.core.SQLDB().QueryContext(ctx, fmt.Sprintf("SELECT role_id FROM iam_user_roles WHERE user_id=%s", bind(e.core, 1)), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var rid string
		if err := rows.Scan(&rid); err != nil {
			return nil, err
		}
		out = append(out, rid)
	}
	return out, rows.Err()
}

func (e *UsersResource) replaceUserRoles(ctx context.Context, userID string, roleIDs []string) error {
	if roleIDs == nil {
		return nil
	}
	if _, err := e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_user_roles WHERE user_id=%s", bind(e.core, 1)), userID); err != nil {
		return httpx.NewError(500, "unknown", err)
	}
	for _, rid := range roleIDs {
		rid = strings.TrimSpace(rid)
		if rid == "" {
			continue
		}
		q := fmt.Sprintf("INSERT INTO iam_user_roles (user_id, role_id) VALUES (%s,%s)", bind(e.core, 1), bind(e.core, 2))
		if _, err := e.core.SQLDB().ExecContext(ctx, q, userID, rid); err != nil {
			return httpx.NewError(500, "unknown", err)
		}
	}
	return nil
}

