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

func (e *RolesResource) ListOrGetMany(ctx context.Context, in *rolesListInput) (*PageResponse[RoleDTO], error) {
	if strings.TrimSpace(in.ID) != "" {
		items, err := e.getMany(ctx, splitIDs(in.ID))
		if err != nil {
			return nil, err
		}
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

	type countRow struct {
		Total int64 `dbx:"total"`
	}
	type roleRow struct {
		ID          string `dbx:"id"`
		Name        string `dbx:"name"`
		Description string `dbx:"description"`
		CreatedAt   int64  `dbx:"created_at"`
	}

	predicates := make([]querydsl.Predicate, 0, 3)
	if v := strings.TrimSpace(in.NameLike); v != "" {
		predicates = append(predicates, querydsl.Like(dbxrepo.Roles.Name, "%"+v+"%"))
	}
	if v := strings.TrimSpace(in.Q); v != "" {
		predicates = append(predicates, querydsl.Or(
			querydsl.Like(dbxrepo.Roles.Name, "%"+v+"%"),
			querydsl.Like(dbxrepo.Roles.Description, "%"+v+"%"),
		))
	}
	where := querydsl.And(predicates...)

	countQuery := querydsl.
		Select(querydsl.CountAll().As("total")).
		From(dbxrepo.Roles).
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
		Select(dbxrepo.Roles.ID, dbxrepo.Roles.Name, dbxrepo.Roles.Description, dbxrepo.Roles.CreatedAt).
		From(dbxrepo.Roles).
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
				ord = dbxrepo.Roles.ID.Desc()
			} else {
				ord = dbxrepo.Roles.ID.Asc()
			}
		case "name":
			if desc {
				ord = dbxrepo.Roles.Name.Desc()
			} else {
				ord = dbxrepo.Roles.Name.Asc()
			}
		case "createdAt":
			if desc {
				ord = dbxrepo.Roles.CreatedAt.Desc()
			} else {
				ord = dbxrepo.Roles.CreatedAt.Asc()
			}
		default:
			return nil, httpx.NewError(400, "validation", fmt.Errorf("invalid sort field: %s", sort))
		}
		listQuery = listQuery.OrderBy(ord)
	}

	rows, err := dbx.QueryAll(ctx, e.core, listQuery, mapper.MustStructMapper[roleRow]())
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}

	items := make([]RoleDTO, 0, int(in.PageSize))
	if rows != nil {
		rows.Range(func(_ int, r roleRow) bool {
			gids, gerr := e.listRoleGroupIDs(ctx, r.ID)
			if gerr != nil {
				err = gerr
				return false
			}
			items = append(items, RoleDTO{
				ID:                 r.ID,
				Name:               r.Name,
				Description:        r.Description,
				PermissionGroupIDs: gids,
				CreatedAt:          unixMilliToRFC3339(r.CreatedAt),
			})
			return true
		})
	}
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
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
	gids, err := e.listRoleGroupIDs(ctx, id)
	if err != nil {
		return nil, err
	}
	return &RoleDTO{ID: id, Name: name, Description: desc, PermissionGroupIDs: gids, CreatedAt: unixMilliToRFC3339(createdAt)}, nil
}

func (e *RolesResource) GetByID(ctx context.Context, in *userIDPath) (*RoleDTO, error) {
	return e.Get(ctx, in)
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

func (e *RolesResource) UpdateByID(ctx context.Context, in *updateRoleInput) (*RoleDTO, error) {
	return e.Update(ctx, in)
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
	if _, err := e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_user_roles WHERE role_id=%s", bind(e.core, 1)), id); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	if _, err := e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_role_permission_groups WHERE role_id=%s", bind(e.core, 1)), id); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	if _, err := e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_roles WHERE id=%s", bind(e.core, 1)), id); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	return &struct{}{}, nil
}

func (e *RolesResource) DeleteByID(ctx context.Context, in *userIDPath) (*struct{}, error) {
	return e.Delete(ctx, in)
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
		if _, err := e.Delete(ctx, &userIDPath{ID: id}); err != nil {
			return nil, err
		}
	}
	return &out, nil
}

func (e *RolesResource) listRoleGroupIDs(ctx context.Context, roleID string) ([]string, error) {
	rows, err := e.core.SQLDB().QueryContext(ctx, fmt.Sprintf("SELECT group_id FROM iam_role_permission_groups WHERE role_id=%s", bind(e.core, 1)), roleID)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for rows.Next() {
		var gid string
		if err := rows.Scan(&gid); err != nil {
			closeRows(rows)
			return nil, err
		}
		out = append(out, gid)
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

