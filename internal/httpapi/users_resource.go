package httpapi

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/arcgolabs/authx"
	"github.com/DaiYuANg/arcgo/kvx"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/mapper"
	"github.com/arcgolabs/dbx/querydsl"
	"github.com/arcgolabs/httpx"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/infra/dbxrepo"
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
	httpx.MustAuto(g,
		httpx.Auto(e.ListOrGetMany),
		httpx.Auto(e.GetByID),
		httpx.Auto(e.Create),
		httpx.Auto(e.UpdateByID),
		httpx.Auto(e.DeleteByID),
	)
	httpx.MustGroupPost(g, "/bulk", e.CreateMany)
	httpx.MustGroupPatch(g, "/bulk", e.UpdateMany)
	httpx.MustGroupDelete(g, "", e.DeleteManyOrGetMany)
}

func (e *UsersResource) List(ctx context.Context, in *usersListInput) (*PageResponse[UserDTO], error) {
	if e.core == nil {
		return nil, httpx.NewError(500, "db_missing")
	}
	if in.Page <= 0 || in.PageSize <= 0 {
		return nil, httpx.NewError(400, "validation", fmt.Errorf("page and pageSize are required"))
	}

	type countRow struct {
		Total int64 `dbx:"total"`
	}
	type userRow struct {
		ID        string `dbx:"id"`
		Email     string `dbx:"email"`
		Name      string `dbx:"name"`
		CreatedAt int64  `dbx:"created_at"`
	}

	predicates := make([]querydsl.Predicate, 0, 4)
	if v := strings.TrimSpace(in.NameLike); v != "" {
		predicates = append(predicates, querydsl.Like(dbxrepo.Users.Name, "%"+v+"%"))
	}
	if v := strings.TrimSpace(in.EmailLike); v != "" {
		predicates = append(predicates, querydsl.Like(dbxrepo.Users.Email, "%"+v+"%"))
	}
	if v := strings.TrimSpace(in.Q); v != "" {
		predicates = append(predicates, querydsl.Or(
			querydsl.Like(dbxrepo.Users.Name, "%"+v+"%"),
			querydsl.Like(dbxrepo.Users.Email, "%"+v+"%"),
		))
	}
	where := querydsl.And(predicates...)

	countQuery := querydsl.
		Select(querydsl.CountAll().As("total")).
		From(dbxrepo.Users).
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
		Select(dbxrepo.Users.ID, dbxrepo.Users.Email, dbxrepo.Users.Name, dbxrepo.Users.CreatedAt).
		From(dbxrepo.Users).
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
				ord = dbxrepo.Users.ID.Desc()
			} else {
				ord = dbxrepo.Users.ID.Asc()
			}
		case "email":
			if desc {
				ord = dbxrepo.Users.Email.Desc()
			} else {
				ord = dbxrepo.Users.Email.Asc()
			}
		case "name":
			if desc {
				ord = dbxrepo.Users.Name.Desc()
			} else {
				ord = dbxrepo.Users.Name.Asc()
			}
		case "createdAt":
			if desc {
				ord = dbxrepo.Users.CreatedAt.Desc()
			} else {
				ord = dbxrepo.Users.CreatedAt.Asc()
			}
		default:
			return nil, httpx.NewError(400, "validation", fmt.Errorf("invalid sort field: %s", sort))
		}
		listQuery = listQuery.OrderBy(ord)
	}

	rows, err := dbx.QueryAll(ctx, e.core, listQuery, mapper.MustStructMapper[userRow]())
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}

	items := make([]UserDTO, 0, int(in.PageSize))
	if rows != nil {
		rows.Range(func(_ int, r userRow) bool {
			items = append(items, UserDTO{
				ID:        r.ID,
				Email:     r.Email,
				Name:      r.Name,
				CreatedAt: unixMilliToRFC3339(r.CreatedAt),
			})
			return true
		})
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
	roleIDs, err := e.listUserRoleIDs(ctx, id)
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	return &UserDTO{ID: id, Email: email, Name: name, RoleIDs: roleIDs, CreatedAt: unixMilliToRFC3339(createdAt)}, nil
}

func (e *UsersResource) GetByID(ctx context.Context, in *userIDPath) (*UserDTO, error) {
	return e.Get(ctx, in)
}

type createUserInput struct {
	Body UserDTO `json:"body"`
}

func (e *UsersResource) Create(ctx context.Context, in *createUserInput) (*UserDTO, error) {
	u := in.Body
	if err := normalizeUserCreate(&u); err != nil {
		return nil, err
	}
	return e.createUser(ctx, u)
}

func normalizeUserCreate(u *UserDTO) error {
	if u == nil {
		return httpx.NewError(422, "validation")
	}
	u.ID = strings.TrimSpace(u.ID)
	u.Email = strings.TrimSpace(u.Email)
	u.Name = strings.TrimSpace(u.Name)
	if u.Email == "" || u.Name == "" {
		return httpx.NewError(422, "validation")
	}
	return nil
}

func (e *UsersResource) createUser(ctx context.Context, u UserDTO) (*UserDTO, error) {
	now, err := nowAndEnforce(ctx, e.core, e.engine, "users:write", "/users")
	if err != nil {
		return nil, err
	}

	ent := dbxrepo.User{
		ID:        u.ID,
		Email:     u.Email,
		Name:      u.Name,
		CreatedAt: now,
	}
	if err := repoCreate(ctx, e.core, dbxrepo.Users, &ent); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	u.ID = ent.ID
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

func (e *UsersResource) UpdateByID(ctx context.Context, in *updateUserInput) (*UserDTO, error) {
	return e.Update(ctx, in)
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
	if _, err := e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_user_roles WHERE user_id=%s", bind(e.core, 1)), id); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	if _, err := e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_users WHERE id=%s", bind(e.core, 1)), id); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	return &struct{}{}, nil
}

func (e *UsersResource) DeleteByID(ctx context.Context, in *userIDPath) (*struct{}, error) {
	return e.Delete(ctx, in)
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
		if _, err := e.Delete(ctx, &userIDPath{ID: id}); err != nil {
			return nil, err
		}
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
	out := []string{}
	for rows.Next() {
		var rid string
		if err := rows.Scan(&rid); err != nil {
			closeRows(rows)
			return nil, err
		}
		out = append(out, rid)
	}
	if err := rows.Err(); err != nil {
		closeRows(rows)
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return out, nil
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

