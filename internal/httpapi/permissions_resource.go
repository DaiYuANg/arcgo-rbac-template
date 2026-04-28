package httpapi

import (
	"context"
	"errors"
	"strings"

	iamservice "github.com/arcgolabs/arcgo-rbac-template/internal/iam/application/service"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/authx"
	"github.com/arcgolabs/httpx"
)

type PermissionsResource struct {
	engine *authx.Engine
	svc    iamservice.PermissionsService
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
	Page     int64  `minimum:"1"       query:"page"     validate:"required_without=ID,omitempty,min=1"`
	PageSize int64  `minimum:"1"       query:"pageSize" validate:"required_without=ID,omitempty,min=1"`
	Q        string `query:"q"`
	Sort     string `query:"sort"`
	Order    string `query:"order"`
	NameLike string `query:"name_like"`
	CodeLike string `query:"code_like"`
}

func (e *PermissionsResource) Register(registrar httpx.Registrar) {
	g := registrar.Scope()
	httpx.MustGroupGet(g, "", e.ListOrGetMany)
	httpx.MustAuto(g,
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
				items = append(items, item.Body)
			}
		}
		pageSize := int64(len(items))
		return &PageResponse[PermissionDTO]{Body: PagePayload[PermissionDTO]{Items: items, Total: pageSize, Page: 1, PageSize: pageSize}}, nil
	}
	return e.List(ctx, in)
}

func (e *PermissionsResource) List(ctx context.Context, in *permListInput) (*PageResponse[PermissionDTO], error) {
	page, err := e.svc.List(ctx, domain.PermissionsListQuery{
		PageParams: domain.PageParams{Page: in.Page, PageSize: in.PageSize},
		Q:          strings.TrimSpace(in.Q),
		Sort:       strings.TrimSpace(in.Sort),
		Order:      domain.NormalizeOrder(in.Order),
		NameLike:   strings.TrimSpace(in.NameLike),
		CodeLike:   strings.TrimSpace(in.CodeLike),
	})
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}

	items := make([]PermissionDTO, 0, len(page.Items))
	for _, p := range page.Items {
		_, gid, gerr := e.svc.Get(ctx, p.ID)
		if gerr != nil && !errors.Is(gerr, domain.ErrNotFound) {
			return nil, httpx.NewError(500, "unknown", gerr)
		}
		var groupID *string
		if gid != nil {
			v := string(*gid)
			groupID = &v
		}
		items = append(items, PermissionDTO{
			ID:        string(p.ID),
			Name:      p.Name,
			Code:      p.Code,
			GroupID:   groupID,
			CreatedAt: unixMilliToRFC3339(p.CreatedAt),
		})
	}
	return &PageResponse[PermissionDTO]{Body: PagePayload[PermissionDTO]{Items: items, Total: page.Total, Page: page.Page, PageSize: page.PageSize}}, nil
}

func (e *PermissionsResource) Get(ctx context.Context, in *userIDPath) (*JSONBody[PermissionDTO], error) {
	id := strings.TrimSpace(in.ID)
	p, gid, err := e.svc.Get(ctx, domain.PermissionID(id))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, httpx.NewError(404, "not_found", err)
		}
		return nil, httpx.NewError(500, "unknown", err)
	}
	var groupID *string
	if gid != nil {
		v := string(*gid)
		groupID = &v
	}
	return wrapJSON(&PermissionDTO{
		ID:        string(p.ID),
		Name:      p.Name,
		Code:      p.Code,
		GroupID:   groupID,
		CreatedAt: unixMilliToRFC3339(p.CreatedAt),
	}), nil
}

func (e *PermissionsResource) GetByID(ctx context.Context, in *userIDPath) (*JSONBody[PermissionDTO], error) {
	return e.Get(ctx, in)
}

type createPermInput struct {
	Body PermissionDTO `json:"body" validate:"required"`
}

func (e *PermissionsResource) Create(ctx context.Context, in *createPermInput) (*JSONBody[PermissionDTO], error) {
	p := in.Body
	if err := normalizePermissionCreate(&p); err != nil {
		return nil, err
	}
	dto, err := e.createPermission(ctx, p)
	if err != nil {
		return nil, err
	}
	return wrapJSON(dto), nil
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
	if err := enforce(ctx, e.engine, "permissions:write", "/permissions"); err != nil {
		return nil, err
	}
	now := nowUnixMilli()
	var gid *domain.PermissionGroupID
	if p.GroupID != nil {
		v := strings.TrimSpace(*p.GroupID)
		if v != "" {
			tmp := domain.PermissionGroupID(v)
			gid = &tmp
		}
	}
	created, outGID, err := e.svc.Create(ctx, domain.Permission{
		ID:        domain.PermissionID(p.ID),
		Name:      p.Name,
		Code:      p.Code,
		CreatedAt: now,
	}, gid)
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	p.ID = string(created.ID)
	p.Name = created.Name
	p.Code = created.Code
	p.CreatedAt = unixMilliToRFC3339(created.CreatedAt)
	p.GroupID = nil
	if outGID != nil {
		v := string(*outGID)
		p.GroupID = &v
	}
	return &p, nil
}

type createPermBulkInput struct {
	Body BulkItems[PermissionDTO] `json:"body"`
}

func (e *PermissionsResource) CreateMany(ctx context.Context, in *createPermBulkInput) (*BulkResponse[PermissionDTO], error) {
	out := make([]PermissionDTO, 0, len(in.Body.Items))
	for _, item := range in.Body.Items {
		created, err := e.Create(ctx, &createPermInput{Body: item})
		if err != nil {
			return nil, err
		}
		out = append(out, created.Body)
	}
	return &BulkResponse[PermissionDTO]{Body: BulkPayload[PermissionDTO]{Items: out}}, nil
}

type updatePermInput struct {
	ID   string        `path:"id"   validate:"required"`
	Body PermissionDTO `json:"body" validate:"required"`
}

func (e *PermissionsResource) Update(ctx context.Context, in *updatePermInput) (*JSONBody[PermissionDTO], error) {
	if err := enforce(ctx, e.engine, "permissions:write", "/permissions"); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(in.ID)
	name := strings.TrimSpace(in.Body.Name)
	code := strings.TrimSpace(in.Body.Code)
	if id == "" || name == "" || code == "" {
		return nil, httpx.NewError(422, "validation")
	}
	var gid *domain.PermissionGroupID
	if in.Body.GroupID != nil {
		v := strings.TrimSpace(*in.Body.GroupID)
		if v != "" {
			tmp := domain.PermissionGroupID(v)
			gid = &tmp
		}
	}
	updated, outGID, err := e.svc.Update(ctx, domain.Permission{ID: domain.PermissionID(id), Name: name, Code: code}, gid)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, httpx.NewError(404, "not_found", err)
		}
		return nil, httpx.NewError(500, "unknown", err)
	}
	var groupID *string
	if outGID != nil {
		v := string(*outGID)
		groupID = &v
	}
	return wrapJSON(&PermissionDTO{
		ID:        string(updated.ID),
		Name:      updated.Name,
		Code:      updated.Code,
		GroupID:   groupID,
		CreatedAt: unixMilliToRFC3339(updated.CreatedAt),
	}), nil
}

func (e *PermissionsResource) UpdateByID(ctx context.Context, in *updatePermInput) (*JSONBody[PermissionDTO], error) {
	return e.Update(ctx, in)
}

func (e *PermissionsResource) Delete(ctx context.Context, in *userIDPath) (*struct{}, error) {
	if err := enforce(ctx, e.engine, "permissions:write", "/permissions"); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(in.ID)
	if err := e.svc.Delete(ctx, domain.PermissionID(id)); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	return &struct{}{}, nil
}

func (e *PermissionsResource) DeleteByID(ctx context.Context, in *userIDPath) (*struct{}, error) {
	return e.Delete(ctx, in)
}
