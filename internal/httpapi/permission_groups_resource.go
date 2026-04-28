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

type PermissionGroupsResource struct {
	engine *authx.Engine
	svc    iamservice.PermissionGroupsService
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
	Page     int64  `minimum:"1"       query:"page"     validate:"required_without=ID,omitempty,min=1"`
	PageSize int64  `minimum:"1"       query:"pageSize" validate:"required_without=ID,omitempty,min=1"`
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
	page, err := e.svc.List(ctx, domain.PermissionGroupsListQuery{
		PageParams: domain.PageParams{Page: in.Page, PageSize: in.PageSize},
		Q:          strings.TrimSpace(in.Q),
		Sort:       strings.TrimSpace(in.Sort),
		Order:      domain.NormalizeOrder(in.Order),
		NameLike:   strings.TrimSpace(in.NameLike),
	})
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	items := make([]PermissionGroupDTO, 0, len(page.Items))
	for _, g := range page.Items {
		items = append(items, PermissionGroupDTO{
			ID:          string(g.ID),
			Name:        g.Name,
			Description: g.Description,
			CreatedAt:   unixMilliToRFC3339(g.CreatedAt),
		})
	}
	return &PageResponse[PermissionGroupDTO]{Items: items, Total: page.Total, Page: page.Page, PageSize: page.PageSize}, nil
}

func (e *PermissionGroupsResource) Get(ctx context.Context, in *userIDPath) (*PermissionGroupDTO, error) {
	id := strings.TrimSpace(in.ID)
	g, err := e.svc.Get(ctx, domain.PermissionGroupID(id))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, httpx.NewError(404, "not_found", err)
		}
		return nil, httpx.NewError(500, "unknown", err)
	}
	return &PermissionGroupDTO{
		ID:          string(g.ID),
		Name:        g.Name,
		Description: g.Description,
		CreatedAt:   unixMilliToRFC3339(g.CreatedAt),
	}, nil
}

func (e *PermissionGroupsResource) GetByID(ctx context.Context, in *userIDPath) (*PermissionGroupDTO, error) {
	return e.Get(ctx, in)
}

type createPGInput struct {
	Body PermissionGroupDTO `json:"body" validate:"required"`
}

func (e *PermissionGroupsResource) Create(ctx context.Context, in *createPGInput) (*PermissionGroupDTO, error) {
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
	created, err := e.svc.Create(ctx, domain.PermissionGroup{
		ID:          domain.PermissionGroupID(pg.ID),
		Name:        pg.Name,
		Description: desc,
		CreatedAt:   now,
	})
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	pg.ID = string(created.ID)
	pg.Name = created.Name
	pg.Description = created.Description
	pg.CreatedAt = unixMilliToRFC3339(created.CreatedAt)
	return &pg, nil
}

type createPGBulkInput struct {
	Body BulkItems[PermissionGroupDTO] `json:"body"`
}

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
	ID   string             `path:"id"   validate:"required"`
	Body PermissionGroupDTO `json:"body" validate:"required"`
}

func (e *PermissionGroupsResource) Update(ctx context.Context, in *updatePGInput) (*PermissionGroupDTO, error) {
	if err := enforce(ctx, e.engine, "permission-groups:write", "/permission-groups"); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(in.ID)
	name := strings.TrimSpace(in.Body.Name)
	desc := strings.TrimSpace(in.Body.Description)
	if id == "" || name == "" {
		return nil, httpx.NewError(422, "validation")
	}
	updated, err := e.svc.Update(ctx, domain.PermissionGroup{ID: domain.PermissionGroupID(id), Name: name, Description: desc})
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, httpx.NewError(404, "not_found", err)
		}
		return nil, httpx.NewError(500, "unknown", err)
	}
	return &PermissionGroupDTO{
		ID:          string(updated.ID),
		Name:        updated.Name,
		Description: updated.Description,
		CreatedAt:   unixMilliToRFC3339(updated.CreatedAt),
	}, nil
}

func (e *PermissionGroupsResource) UpdateByID(ctx context.Context, in *updatePGInput) (*PermissionGroupDTO, error) {
	return e.Update(ctx, in)
}

type updatePGBulkInput struct {
	ID   string             `query:"id"`
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
	if err := enforce(ctx, e.engine, "permission-groups:write", "/permission-groups"); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(in.ID)
	if err := e.svc.Delete(ctx, domain.PermissionGroupID(id)); err != nil {
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
