package httpapi

import (
	"context"
	"fmt"
	"strings"

	"github.com/arcgolabs/authx"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/column"
	"github.com/arcgolabs/dbx/mapper"
	"github.com/arcgolabs/dbx/querydsl"
	"github.com/arcgolabs/httpx"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/infra/dbxrepo"
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

	type countRow struct {
		Total int64 `dbx:"total"`
	}
	type permRow struct {
		ID        string `dbx:"id"`
		Name      string `dbx:"name"`
		Code      string `dbx:"code"`
		CreatedAt int64  `dbx:"created_at"`
		GroupID   *string `dbx:"group_id"`
	}

	predicates := make([]querydsl.Predicate, 0, 4)
	if v := strings.TrimSpace(in.NameLike); v != "" {
		predicates = append(predicates, querydsl.Like(dbxrepo.Permissions.Name, "%"+v+"%"))
	}
	if v := strings.TrimSpace(in.CodeLike); v != "" {
		predicates = append(predicates, querydsl.Like(dbxrepo.Permissions.Code, "%"+v+"%"))
	}
	if v := strings.TrimSpace(in.Q); v != "" {
		predicates = append(predicates, querydsl.Or(
			querydsl.Like(dbxrepo.Permissions.Name, "%"+v+"%"),
			querydsl.Like(dbxrepo.Permissions.Code, "%"+v+"%"),
		))
	}
	where := querydsl.And(predicates...)

	countQuery := querydsl.
		Select(querydsl.CountAll().As("total")).
		From(dbxrepo.Permissions).
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

	// groupId is represented by join-table lookup (0..1 in practice).
	joinTable := querydsl.NamedTable("iam_permission_group_permissions")
	joinPermID := column.Named[string](joinTable, "perm_id")
	joinGroupID := column.Named[*string](joinTable, "group_id")

	listQuery := querydsl.
		Select(
			dbxrepo.Permissions.ID,
			dbxrepo.Permissions.Name,
			dbxrepo.Permissions.Code,
			dbxrepo.Permissions.CreatedAt,
			joinGroupID.As("group_id"),
		).
		From(dbxrepo.Permissions).
		LeftJoin(joinTable).On(joinPermID.EqColumn(dbxrepo.Permissions.ID)).
		Where(where).
		PageBy(int(in.Page), int(in.PageSize))

	rows, err := dbx.QueryAll(ctx, e.core, listQuery, mapper.MustStructMapper[permRow]())
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}

	items := make([]PermissionDTO, 0, int(in.PageSize))
	if rows != nil {
		rows.Range(func(_ int, r permRow) bool {
			items = append(items, PermissionDTO{
				ID:        r.ID,
				Name:      r.Name,
				Code:      r.Code,
				GroupID:   r.GroupID,
				CreatedAt: unixMilliToRFC3339(r.CreatedAt),
			})
			return true
		})
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

func (e *PermissionsResource) GetByID(ctx context.Context, in *userIDPath) (*PermissionDTO, error) {
	return e.Get(ctx, in)
}

type createPermInput struct{ Body PermissionDTO `json:"body"` }

func (e *PermissionsResource) Create(ctx context.Context, in *createPermInput) (*PermissionDTO, error) {
	p := in.Body
	if err := normalizePermissionCreate(&p); err != nil {
		return nil, err
	}
	return e.createPermission(ctx, p)
}

func normalizePermissionCreate(p *PermissionDTO) error {
	if p == nil {
		return httpx.NewError(422, "validation")
	}
	p.ID = strings.TrimSpace(p.ID)
	p.Name = strings.TrimSpace(p.Name)
	p.Code = strings.TrimSpace(p.Code)
	if p.Name == "" || p.Code == "" {
		return httpx.NewError(422, "validation")
	}
	return nil
}

func (e *PermissionsResource) createPermission(ctx context.Context, p PermissionDTO) (*PermissionDTO, error) {
	now, err := nowAndEnforce(ctx, e.core, e.engine, "permissions:write", "/permissions")
	if err != nil {
		return nil, err
	}

	ent := dbxrepo.Permission{
		ID:        p.ID,
		Name:      p.Name,
		Code:      p.Code,
		CreatedAt: now,
	}
	if err := repoCreate(ctx, e.core, dbxrepo.Permissions, &ent); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	p.ID = ent.ID
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

func (e *PermissionsResource) UpdateByID(ctx context.Context, in *updatePermInput) (*PermissionDTO, error) {
	return e.Update(ctx, in)
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
	if _, err := e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_permission_group_permissions WHERE perm_id=%s", bind(e.core, 1)), id); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	if _, err := e.core.SQLDB().ExecContext(ctx, fmt.Sprintf("DELETE FROM iam_permissions WHERE id=%s", bind(e.core, 1)), id); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	return &struct{}{}, nil
}

func (e *PermissionsResource) DeleteByID(ctx context.Context, in *userIDPath) (*struct{}, error) {
	return e.Delete(ctx, in)
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
		if _, err := e.Delete(ctx, &userIDPath{ID: id}); err != nil {
			return nil, err
		}
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

